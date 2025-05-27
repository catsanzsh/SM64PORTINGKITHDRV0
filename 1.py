import tkinter as tk
from tkinter import filedialog, messagebox
import os
import struct
import subprocess
import argparse

try:
    from capstone import *
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

# File signatures for generic asset detection (excluding PNG)
FILE_SIGNATURES = {
    'midi': (b'\x4D\x54\x68\x64', '.mid'),  # MIDI: MThd
    'mp3': (b'\xFF\xFB', '.mp3'),           # MP3: MPEG-1 Layer 3
    'mp3_id3': (b'\x49\x44\x33', '.mp3'),   # MP3: ID3 tag
    'wav': (b'\x52\x49\x46\x46', '.wav'),   # WAV: RIFF
    'jpeg': (b'\xFF\xD8\xFF', '.jpg'),      # JPEG: Start of Image
}

# SM64-specific asset ranges (example offsets, adjust based on actual ROM layout)
SM64_ASSET_RANGES = {
    'level_bank': (0x120000, 0x1A0000, 'level_bank.bin'),  # Example: Level data
    'texture_bank': (0x1A0000, 0x200000, 'texture_bank.bin'),  # Example: Textures
    'model_data': (0x200000, 0x250000, 'model_data.bin'),  # Example: Models
}

def detect_format(rom_data):
    if rom_data[:4] == b'\x80\x37\x12\x40':
        return 'big'  # Big-endian (.z64)
    elif rom_data[:4] == b'\x40\x12\x37\x80':
        return 'little'  # Little-endian (.n64)
    elif rom_data[:4] == b'\x37\x80\x40\x12':
        return 'byteswap'  # Byte-swapped (.v64)
    else:
        raise ValueError("Unknown ROM format")

def convert_to_big_endian(rom_data, format):
    if format == 'big':
        return rom_data
    elif format == 'little':
        return b''.join(struct.pack('>I', struct.unpack('<I', rom_data[i:i+4])[0]) for i in range(0, len(rom_data), 4))
    elif format == 'byteswap':
        return b''.join(rom_data[i+1] + rom_data[i] + rom_data[i+3] + rom_data[i+2] for i in range(0, len(rom_data), 4))

class N64ROMDumper:
    def __init__(self, root=None):
        self.root = root
        self.rom_path = None
        self.rom_data = None
        self.is_sm64 = False  # Flag for SM64 detection
        
        if root:  # GUI mode
            self.root.title("Universal N64 ROM Dumper")
            self.root.geometry("600x400")
            
            self.label = tk.Label(root, text="Select an N64 ROM file (.z64, .n64, .v64)")
            self.label.pack(pady=10)
            
            self.select_button = tk.Button(root, text="Select ROM", command=self.select_rom)
            self.select_button.pack(pady=5)
            
            self.rom_label = tk.Label(root, text="No ROM selected")
            self.rom_label.pack(pady=5)
            
            self.dump_asm_button = tk.Button(root, text="Dump ASM", command=self.dump_asm, state="disabled")
            self.dump_asm_button.pack(pady=5)
            
            self.dump_assets_button = tk.Button(root, text="Dump Assets", command=self.dump_assets, state="disabled")
            self.dump_assets_button.pack(pady=5)
            
            self.decompile_button = tk.Button(root, text="Decompile to C", command=self.decompile_to_c, state="disabled")
            self.decompile_button.pack(pady=5)
            
            self.compile_button = tk.Button(root, text="Compile to EXE", command=self.compile_to_exe, state="disabled")  # New button
            self.compile_button.pack(pady=5)
            
            self.dump_entire_asm_var = tk.BooleanVar(value=True)
            self.dump_entire_asm_check = tk.Checkbutton(root, text="Dump entire ROM as ASM", variable=self.dump_entire_asm_var, command=self.toggle_asm_offset)
            self.dump_entire_asm_check.pack(pady=5)
            
            self.asm_offset_label = tk.Label(root, text="ASM start offset (hex):")
            self.asm_offset_label.pack(pady=5)
            self.asm_offset_entry = tk.Entry(root)
            self.asm_offset_entry.pack(pady=5)
            self.asm_offset_entry.config(state="disabled")
            
            self.asset_ranges_label = tk.Label(root, text="Asset extraction ranges (start end file_name):")
            self.asset_ranges_label.pack(pady=5)
            self.asset_ranges_text = tk.Text(root, height=5, width=60)
            self.asset_ranges_text.pack(pady=5)
            
            self.status = tk.Label(root, text="Status: Idle")
            self.status.pack(pady=10)
            
            self.output_text = tk.Text(root, height=10, width=60)
            self.output_text.pack(pady=10)
            
            if not CAPSTONE_AVAILABLE:
                self.output_text.insert(tk.END, "Error: Capstone not found. Install with 'pip install capstone'.\n")
                self.dump_asm_button.config(state="disabled")

    def toggle_asm_offset(self):
        if self.dump_entire_asm_var.get():
            self.asm_offset_entry.config(state="disabled")
        else:
            self.asm_offset_entry.config(state="normal")

    def select_rom(self, rom_path=None):
        if rom_path or (self.root and not rom_path):
            self.rom_path = rom_path or filedialog.askopenfilename(filetypes=[("N64 ROM files", "*.z64 *.n64 *.v64")])
            if self.rom_path:
                try:
                    with open(self.rom_path, "rb") as rom_file:
                        rom_data = rom_file.read()
                    if len(rom_data) < 4:
                        raise ValueError("ROM file is too small")
                    format = detect_format(rom_data)
                    self.rom_data = convert_to_big_endian(rom_data, format)
                    
                    # SM64 Detection
                    game_title = self.rom_data[0x20:0x34].decode('ascii', errors='ignore').rstrip()
                    self.is_sm64 = game_title.startswith("SUPER MARIO 64")
                    
                    if self.root:
                        self.rom_label.config(text=f"Selected: {os.path.basename(self.rom_path)} ({format})")
                        self.dump_assets_button.config(state="normal")
                        self.decompile_button.config(state="normal")
                        self.compile_button.config(state="normal")
                        if CAPSTONE_AVAILABLE:
                            self.dump_asm_button.config(state="normal")
                        self.status.config(text=f"Status: ROM loaded{' (SM64 detected)' if self.is_sm64 else ''}")
                    return True
                except Exception as e:
                    if self.root:
                        messagebox.showerror("Error", f"Failed to load ROM: {str(e)}")
                    else:
                        print(f"Error: Failed to load ROM: {str(e)}")
                    self.rom_path = None
                    self.rom_data = None
                    return False
        if self.root:
            self.rom_label.config(text="No ROM selected")
            self.dump_asm_button.config(state="disabled")
            self.dump_assets_button.config(state="disabled")
            self.decompile_button.config(state="disabled")
            self.compile_button.config(state="disabled")
            self.status.config(text="Status: Idle")
        return False

    def dump_asm(self, output_dir=None):
        if not self.rom_path or not self.rom_data:
            if self.root:
                messagebox.showerror("Error", "No ROM file selected!")
            else:
                print("Error: No ROM file selected!")
            return
        if not CAPSTONE_AVAILABLE:
            if self.root:
                messagebox.showerror("Error", "Capstone not installed. Install with 'pip install capstone'.")
            return
        
        output_dir = output_dir or (self.root and filedialog.askdirectory(title="Select Output Directory"))
        if not output_dir:
            if self.root:
                self.status.config(text="Status: Output directory not selected")
            return
        
        if self.root:
            self.status.config(text="Status: Dumping ASM...")
            self.output_text.delete(1.0, tk.END)
        
        try:
            start_offset = 0 if (self.root and self.dump_entire_asm_var.get()) else int(self.asm_offset_entry.get(), 16)
            md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN)
            output_file = os.path.join(output_dir, "rom.asm")
            with open(output_file, "w") as asm_file:
                for i in md.disasm(self.rom_data[start_offset:], start_offset):
                    asm_file.write(f"0x{i.address:08X}:\t{i.mnemonic}\t{i.op_str}\n")
            if self.root:
                self.output_text.insert(tk.END, f"Saved {output_file}\n")
                self.status.config(text="Status: ASM dump complete")
                messagebox.showinfo("Success", "ASM dumped successfully")
            else:
                print(f"Saved {output_file}")
        except Exception as e:
            if self.root:
                self.status.config(text="Status: Error during ASM dump")
                self.output_text.insert(tk.END, f"Error: {str(e)}\n")
                messagebox.showerror("Error", f"Failed to dump ASM: {str(e)}")
            else:
                print(f"Error: {str(e)}")

    def dump_assets(self, output_dir=None):
        if not self.rom_path or not self.rom_data:
            if self.root:
                messagebox.showerror("Error", "No ROM file selected!")
            else:
                print("Error: No ROM file selected!")
            return
        
        output_dir = output_dir or (self.root and filedialog.askdirectory(title="Select Output Directory"))
        if not output_dir:
            if self.root:
                self.status.config(text="Status: Output directory not selected")
            return
        
        if self.root:
            self.status.config(text="Status: Dumping assets...")
            self.output_text.delete(1.0, tk.END)
        
        try:
            if self.is_sm64:
                # SM64-specific asset extraction
                for asset_name, (start, end, file_name) in SM64_ASSET_RANGES.items():
                    if start < len(self.rom_data) and end <= len(self.rom_data):
                        data = self.rom_data[start:end]
                        output_file = os.path.join(output_dir, file_name)
                        with open(output_file, "wb") as asset_file:
                            asset_file.write(data)
                        if self.root:
                            self.output_text.insert(tk.END, f"Saved SM64 {asset_name}: {file_name}\n")
                        else:
                            print(f"Saved SM64 {asset_name}: {file_name}")
            else:
                # Generic asset detection (unchanged logic, abbreviated for brevity)
                ranges_text = self.root and self.asset_ranges_text.get("1.0", tk.END).strip()
                if ranges_text:
                    for line in ranges_text.split('\n'):
                        start, end, file_name = line.split()
                        start, end = int(start, 16), int(end, 16)
                        data = self.rom_data[start:end]
                        output_file = os.path.join(output_dir, file_name)
                        with open(output_file, "wb") as asset_file:
                            asset_file.write(data)
                        if self.root:
                            self.output_text.insert(tk.END, f"Saved {file_name}\n")
                        else:
                            print(f"Saved {file_name}")
                else:
                    offset, asset_count = 0, 0
                    while offset < len(self.rom_data):
                        for file_type, (signature, ext) in FILE_SIGNATURES.items():
                            if self.rom_data[offset:offset+len(signature)] == signature:
                                end_offset = offset + 1024  # Simplified size estimation
                                data = self.rom_data[offset:end_offset]
                                file_name = f"asset_{asset_count:04d}_{offset:08X}{ext}"
                                output_file = os.path.join(output_dir, file_name)
                                with open(output_file, "wb") as asset_file:
                                    asset_file.write(data)
                                if self.root:
                                    self.output_text.insert(tk.END, f"Saved {file_name} ({file_type})\n")
                                else:
                                    print(f"Saved {file_name} ({file_type})")
                                asset_count += 1
                                offset = end_offset
                                break
                        else:
                            offset += 1
            
            if self.root:
                self.status.config(text="Status: Asset dump complete")
                messagebox.showinfo("Success", "Assets dumped successfully")
        except Exception as e:
            if self.root:
                self.status.config(text="Status: Error during asset dump")
                self.output_text.insert(tk.END, f"Error: {str(e)}\n")
                messagebox.showerror("Error", f"Failedluor to dump assets: {str(e)}")
            else:
                print(f"Error: {str(e)}")

    def decompile_to_c(self, output_dir=None, ghidra_dir=None):
        if not self.rom_path or not self.rom_data:
            if self.root:
                messagebox.showerror("Error", "No ROM file selected!")
            else:
                print("Error: No ROM file selected!")
            return
        
        ghidra_dir = ghidra_dir or (self.root and filedialog.askdirectory(title="Select Ghidra Installation Directory"))
        output_dir = output_dir or (self.root and filedialog.askdirectory(title="Select Output Directory"))
        if not (ghidra_dir and output_dir):
            if self.root:
                self.status.config(text="Status: Directory not selected")
            return
        
        if self.root:
            self.status.config(text="Status: Decompiling to C...")
            self.output_text.delete(1.0, tk.END)
        
        script_path = os.path.join(os.path.dirname(__file__), "Decompile.java")
        project_path, project_name = output_dir, "temp_project"
        output_file = os.path.join(output_dir, f"decompiled_{os.path.splitext(os.path.basename(self.rom_path))[0]}.c")
        analyze_headless = os.path.join(ghidra_dir, "support", "analyzeHeadless.bat" if os.name == 'nt' else "analyzeHeadless")
        
        cmd = [analyze_headless, project_path, project_name, "-import", self.rom_path, "-postScript", script_path, output_file, "-deleteProject"]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            if self.root:
                self.output_text.insert(tk.END, f"Saved {os.path.basename(output_file)}\n")
                self.status.config(text="Status: Decompilation complete")
                messagebox.showinfo("Success", f"Decompilation complete: {os.path.basename(output_file)}")
            else:
                print(f"Saved {output_file}")
        except Exception as e:
            if self.root:
                self.status.config(text="Status: Decompilation failed")
                self.output_text.insert(tk.END, f"Error: {str(e)}\n")
                messagebox.showerror("Error", f"Failed to decompile: {str(e)}")
            else:
                print(f"Error: {str(e)}")

    def compile_to_exe(self, output_dir=None, n64recomp_path=None):
        if not self.rom_path or not self.rom_data:
            if self.root:
                messagebox.showerror("Error", "No ROM file selected!")
            else:
                print("Error: No ROM file selected!")
            return
        
        output_dir = output_dir or (self.root and filedialog.askdirectory(title="Select Output Directory"))
        n64recomp_path = n64recomp_path or (self.root and filedialog.askopenfilename(title="Select N64Recomp Executable", filetypes=[("Executables", "*.exe" if os.name == 'nt' else "*")]))
        if not (output_dir and n64recomp_path):
            if self.root:
                self.status.config(text="Status: Directory or N64Recomp not selected")
            return
        
        if self.root:
            self.status.config(text="Status: Compiling to EXE...")
            self.output_text.delete(1.0, tk.END)
        
        try:
            # Prepare decompiled C code
            c_file = os.path.join(output_dir, f"decompiled_{os.path.splitext(os.path.basename(self.rom_path))[0]}.c")
            if not os.path.exists(c_file):
                self.decompile_to_c(output_dir)
                if not os.path.exists(c_file):
                    raise FileNotFoundError("Decompiled C file not generated")
            
            # Configuration for N64Recomp
            config_file = os.path.join(os.path.dirname(__file__), "sm64_config.yaml") if self.is_sm64 else filedialog.askopenfilename(title="Select N64Recomp Config YAML", filetypes=[("YAML files", "*.yaml *.yml")])
            if not config_file or not os.path.exists(config_file):
                raise FileNotFoundError("N64Recomp configuration file required")
            
            output_exe = os.path.join(output_dir, f"{os.path.splitext(os.path.basename(self.rom_path))[0]}_recomp.exe")
            cmd = [n64recomp_path, "--input", c_file, "--config", config_file, "--output", output_exe]
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            
            if self.root:
                self.output_text.insert(tk.END, f"Saved {output_exe}\n")
                self.status.config(text="Status: Compilation complete")
                messagebox.showinfo("Success", f"Compiled to {os.path.basename(output_exe)}")
            else:
                print(f"Saved {output_exe}")
        except Exception as e:
            if self.root:
                self.status.config(text="Status: Compilation failed")
                self.output_text.insert(tk.END, f"Error: {str(e)}\n")
                messagebox.showerror("Error", f"Failed to compile: {str(e)}")
            else:
                print(f"Error: {str(e)}")

def run_from_script(args):
    dumper = N64ROMDumper()
    if dumper.select_rom(args.rom):
        if args.dump_asm:
            dumper.dump_asm(args.output)
        if args.dump_assets:
            dumper.dump_assets(args.output)
        if args.decompile:
            dumper.decompile_to_c(args.output, args.ghidra_dir)
        if args.compile:
            dumper.compile_to_exe(args.output, args.n64recomp_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="N64 ROM Dumper with SM64 Features")
    parser.add_argument("--rom", help="Path to ROM file")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--dump-asm", action="store_true", help="Dump ASM")
    parser.add_argument("--dump-assets", action="store_true", help="Dump assets")
    parser.add_argument("--decompile", action="store_true", help="Decompile to C")
    parser.add_argument("--compile", action="store_true", help="Compile to EXE")
    parser.add_argument("--ghidra-dir", help="Ghidra installation directory")
    parser.add_argument("--n64recomp-path", help="Path to N64Recomp executable")
    args = parser.parse_args()
    
    if args.rom:
        run_from_script(args)
    else:
        root = tk.Tk()
        app = N64ROMDumper(root)
        root.mainloop()
