#![no_std]

#[macro_use]
extern crate alloc;

pub mod frame;
pub mod heap;

pub fn init() {
    heap::init();
}
