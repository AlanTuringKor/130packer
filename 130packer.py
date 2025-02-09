import pefile
import sys
import os
from itertools import cycle
import struct
import shutil

class SimplePacker:
    def __init__(self, input_file):
        self.input_file = input_file
        self.pe = pefile.PE(input_file)
        self.original_entry = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        self.packed_data = None
        
    def simple_xor_encrypt(self, data, key=0x42):
        """Simple XOR encryption/decryption."""
        return bytes(b ^ key for b in data)
    
    def pack(self):
        # Get the code section
        code_section = None
        for section in self.pe.sections:
            if section.Name.startswith(b'.text'):
                code_section = section
                break
                
        if not code_section:
            raise Exception("Code section not found")
            
        # Read the code section data
        code_data = code_section.get_data()
        
        # Encrypt the code section
        self.packed_data = self.simple_xor_encrypt(code_data)
        
        # Create a new section for our stub and encrypted code
        new_section_name = b'.packed\x00\x00'
        new_section_size = len(self.packed_data) + 256  # Extra space for stub
        
        # Align section size
        section_align = self.pe.OPTIONAL_HEADER.SectionAlignment
        new_section_size = ((new_section_size + section_align - 1) // section_align) * section_align
        
        # Create new section
        new_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__)
        new_section.Name = new_section_name
        new_section.Misc_VirtualSize = new_section_size
        new_section.VirtualAddress = self.pe.sections[-1].VirtualAddress + \
                                   self.pe.sections[-1].Misc_VirtualSize
        new_section.SizeOfRawData = new_section_size
        new_section.PointerToRawData = self.pe.sections[-1].PointerToRawData + \
                                     self.pe.sections[-1].SizeOfRawData
        new_section.Characteristics = 0xE0000020  # Read, Write, Execute, Code
        
        # Generate stub (simplified example)
        stub = bytes([
            0x60,                      # pushad
            0xB8, 0x00, 0x00, 0x00, 0x00,  # mov eax, <decrypt_start>
            0xB9, 0x00, 0x00, 0x00, 0x00,  # mov ecx, <size>
            0xBA, 0x42, 0x00, 0x00, 0x00,  # mov edx, 0x42 (XOR key)
        ])
        
        # Add decrypt loop
        stub += bytes([
            0x80, 0x30, 0x42,         # xor byte ptr [eax], 0x42
            0x40,                      # inc eax
            0xE2, 0xFA,               # loop decrypt
            0x61,                      # popad
            0xE9, 0x00, 0x00, 0x00, 0x00  # jmp original_entry
        ])
        
        # Update section with stub and encrypted data
        section_data = bytearray(new_section_size)
        section_data[:len(stub)] = stub
        section_data[len(stub):len(stub) + len(self.packed_data)] = self.packed_data
        
        # Add new section
        self.pe.sections.append(new_section)
        self.pe.__structures__.append(new_section)
        
        # Update PE header
        self.pe.FILE_HEADER.NumberOfSections += 1
        self.pe.OPTIONAL_HEADER.SizeOfImage = new_section.VirtualAddress + new_section_size
        
        # Change entry point to our stub
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress
        
        # Save packed file
        output_file = self.input_file[:-4] + '_packed.exe'
        self.pe.write(output_file)
        return output_file

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <input_pe_file>")
        return
        
    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"File {input_file} not found")
        return
        
    try:
        packer = SimplePacker(input_file)
        output_file = packer.pack()
        print(f"Successfully packed file: {output_file}")
    except Exception as e:
        print(f"Error packing file: {str(e)}")

if __name__ == "__main__":
    main()
