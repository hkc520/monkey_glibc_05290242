SHELL := /bin/bash
export ROOT_MANIFEST_DIR := $(shell pwd)
RELEASE := release
LOG ?= error
# RISC-V 配置
RISCV_TARGET := riscv64gc-unknown-none-elf
RISCV_ARCH := riscv64
RISCV_KERNEL_ELF := target/$(RISCV_TARGET)/$(RELEASE)/kernel
RISCV_KERNEL_OUT := kernel-rv
RISCV_FEATURES :=   # 根据需要调整，例如启用 virtio 驱动

# LoongArch 配置
LOONGARCH_TARGET := loongarch64-unknown-none
LOONGARCH_ARCH := loongarch64
LOONGARCH_KERNEL_ELF := target/$(LOONGARCH_TARGET)/$(RELEASE)/kernel
LOONGARCH_KERNEL_OUT := kernel-la
LOONGARCH_FEATURES :=   # 根据需要调整

.PHONY: all build-riscv build-loongarch clean

all: build-riscv build-loongarch

build-riscv:
	@echo "Building RISC-V kernel..."
	@if [ -d dotcargo ]; then mv dotcargo .cargo; fi
	@BOARD=qemu LOG=$(LOG) RUSTFLAGS="-Clink-arg=-no-pie --cfg=driver=\"kvirtio\" --cfg=board=\"qemu\" --cfg=root_fs=\"ext4\"" \
	cargo build --target $(RISCV_TARGET) --features "$(RISCV_FEATURES)" --release --offline || exit 1
	@riscv64-unknown-elf-objcopy -O binary $(RISCV_KERNEL_ELF) $(RISCV_KERNEL_OUT)
	@if [ -d .cargo ]; then mv .cargo dotcargo; fi

build-loongarch:
	@echo "Building LoongArch kernel..."
	@if [ -d dotcargo ]; then mv dotcargo .cargo; fi
	@BOARD=qemu LOG=$(LOG) RUSTFLAGS="-Clink-arg=-no-pie --cfg=driver=\"kvirtio\" --cfg=board=\"qemu\" --cfg=root_fs=\"ext4_rs\"" \
	cargo build --target $(LOONGARCH_TARGET) --features "$(LOONGARCH_FEATURES)" --release --offline || exit 1
	@cp $(LOONGARCH_KERNEL_ELF) $(LOONGARCH_KERNEL_OUT) || exit 1
	@if [ -d .cargo ]; then mv .cargo dotcargo; fi


clean:
	@rm -rf target/ kernel-rv kernel-la
