#![no_std]
#![feature(alloc_error_handler)]

#[macro_use]
extern crate alloc;

pub mod frame;
mod heap;

pub fn init() {
    heap::init();
}
