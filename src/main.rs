use std::sync::{Mutex};
use std::time::{Duration, Instant};
use windows::{
    core::*,
    Win32::Foundation::*,
    Win32::System::DataExchange::*,
    Win32::System::Ole::*,
    Win32::System::LibraryLoader::GetModuleHandleW,
    Win32::UI::WindowsAndMessaging::*,
    Win32::System::ProcessStatus::GetModuleBaseNameW,
    Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ},
};

// === 节流控制配置 ===
// 定义节流时间阈值：500毫秒
const THROTTLE_MS: u64 = 500;

// 使用 Mutex 记录上一次打印的时间
// 注意：这里使用 Mutex 是因为我们需要在 immutable 的静态上下文中修改时间
static LAST_UPDATE_LOG: Mutex<Option<Instant>> = Mutex::new(None);

// 辅助函数：检查是否允许打印（节流逻辑）
fn check_throttle(timer: &Mutex<Option<Instant>>) -> bool {
    // 获取锁
    let mut guard = timer.lock().unwrap();
    let now = Instant::now();

    if let Some(last_time) = *guard {
        // 如果距离上次打印的时间小于阈值，则阻止打印
        if now.duration_since(last_time) < Duration::from_millis(THROTTLE_MS) {
            return false;
        }
    }

    // 更新最后打印时间
    *guard = Some(now);
    true
}
// 辅助：将 Rust 字符串转换为 Windows 宽字符串 (UTF-16)
fn to_wstring(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

// Helper: convert last Win32 error into a windows::core::Error
fn last_error() -> Error {
    let code = unsafe { GetLastError().0 };
    Error::from(HRESULT::from_win32(code))
}

// 辅助函数：通过窗口句柄获取 PID 和 进程名
unsafe fn get_process_info(hwnd: HWND) -> Result<(u32, String)> {
    let mut pid: u32 = 0;
    // 获取关联的 PID
    unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };

    if pid == 0 {
        return Err(last_error());
    }

    // 打开进程以查询信息
    // 注意：PROCESS_QUERY_INFORMATION 和 PROCESS_VM_READ 是必须的权限
    let process_handle = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)?
    };

    if process_handle.is_invalid() {
        return Err(last_error());
    }

    // 获取进程名
    let mut buffer = [0u16; MAX_PATH as usize];
    // GetModuleBaseNameW 获取的是文件名 (例如 "notepad.exe")
    // 如果需要完整路径，可以使用 GetModuleFileNameExW
    let len = unsafe {
        GetModuleBaseNameW(process_handle, None, &mut buffer)    
    };
    
    // 关闭句柄防止泄露
    let _ = unsafe { CloseHandle(process_handle) };

    if len == 0 {
        return Err(last_error());
    }

    // 将 u16 数组转换为 String
    let name = String::from_utf16_lossy(&buffer[..len as usize]);
    
    Ok((pid, name))
}

// 核心逻辑 1: 分析剪贴板内容
unsafe fn analyze_clipboard() {
    unsafe {
        let owner_hwnd = GetClipboardOwner();
        match owner_hwnd {
            Ok(hwnd) => {
                println!("Clipboard Owner HWND: {:?}", hwnd);
                // 获取进程信息
                if let Ok((pid, name)) = get_process_info(hwnd) {
                    println!("Clipboard Owner PID: {}, Process Name: {}", pid, name);
                }
            },
            Err(_) => println!("Clipboard Owner HWND: None"),
        };
    }
    // 1. 检查是否是图片内容 (Bitmap)
    let has_bitmap = unsafe { IsClipboardFormatAvailable(CF_BITMAP.0 as u32).is_ok() };
    let has_dib = unsafe { IsClipboardFormatAvailable(CF_DIB.0 as u32).is_ok() };
    if has_bitmap || has_dib {
        println!(">> ALERT: User copied IMAGE CONTENT (Bitmap/Screenshot).");
        return;
    }
}

// 窗口过程函数
unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_CREATE => {
            if unsafe { AddClipboardFormatListener(hwnd).is_err() } {
                eprintln!("Failed to add clipboard format listener.");
                return LRESULT(-1);
            }
            println!("Monitoring started. Rust is watching your clipboard...");
            println!("Try Screenshots.");
            LRESULT(0)
        }
        WM_CLIPBOARDUPDATE => {
            if check_throttle(&LAST_UPDATE_LOG) {
                // println!("-----------------------------------");
                // println!("[Event] Clipboard content changed.");
                unsafe { analyze_clipboard() };    
            }
            LRESULT(0)
        }
        WM_DESTROY => {
            let _ = unsafe { RemoveClipboardFormatListener(hwnd) };
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) },
    }
}

fn main() -> Result<()> {
    unsafe {
        let instance = GetModuleHandleW(None)?;
        let class_name = to_wstring("RustClipboardMonitor");

        let wc = WNDCLASSW {
            hCursor: LoadCursorW(None, IDC_ARROW)?,
            hInstance: instance.into(),
            lpszClassName: PCWSTR(class_name.as_ptr()),
            lpfnWndProc: Some(wnd_proc),
            ..Default::default()
        };

        if RegisterClassW(&wc) == 0 {
            eprintln!("Window Registration Failed!");
            return Ok(());
        }
        
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(to_wstring("Rust Monitor").as_ptr()),
            WINDOW_STYLE::default(),
            0, 0, 0, 0,
            Some(HWND_MESSAGE),
            None,
            Some(instance.into()), //将 instance (HMODULE) 转换为 Option<HINSTANCE>
            None,
        );

        if hwnd.is_err() {
            eprintln!("Window Creation Failed!");
            return Ok(());
        }

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    Ok(())
}
