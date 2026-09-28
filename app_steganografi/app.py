import struct
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from PIL import Image

MAGIC = b"LSB1"
HEADER_SIZE = len(MAGIC) + 4


def _bytes_to_bits(data: bytes):
    for value in data:
        for shift in range(7, -1, -1):
            yield (value >> shift) & 1


def _bits_to_bytes(bits):
    output = bytearray()
    value = 0
    for index, bit in enumerate(bits, start=1):
        value = (value << 1) | bit
        if index % 8 == 0:
            output.append(value)
            value = 0
    return bytes(output)


def max_message_bytes(image: Image.Image) -> int:
    rgb = image.convert("RGB")
    return max(0, (rgb.width * rgb.height * 3 - HEADER_SIZE * 8) // 8)


def embed_message(image: Image.Image, message: str) -> Image.Image:
    rgb = image.convert("RGB")
    payload = message.encode("utf-8")
    capacity = max_message_bytes(rgb)
    if len(payload) > capacity:
        raise ValueError(
            f"Pesan terlalu besar. Kapasitas gambar hanya {capacity:,} byte."
        )

    packet = MAGIC + struct.pack(">I", len(payload)) + payload
    bits = iter(_bytes_to_bits(packet))
    pixels = list(rgb.getdata())
    encoded = []
    for red, green, blue in pixels:
        channels = [red, green, blue]
        for channel_index in range(3):
            try:
                bit = next(bits)
            except StopIteration:
                break
            channels[channel_index] = (channels[channel_index] & 0xFE) | bit
        encoded.append(tuple(channels))

    result = Image.new("RGB", rgb.size)
    result.putdata(encoded)
    return result


def extract_message(image: Image.Image) -> str:
    rgb = image.convert("RGB")
    bits = ((channel & 1) for pixel in rgb.getdata() for channel in pixel)
    header = _bits_to_bytes(next(bits) for _ in range(HEADER_SIZE * 8))
    if header[: len(MAGIC)] != MAGIC:
        raise ValueError("Gambar tidak memiliki pesan LSB yang valid.")

    message_length = struct.unpack(">I", header[len(MAGIC) :])[0]
    available = rgb.width * rgb.height * 3 - HEADER_SIZE * 8
    if message_length * 8 > available:
        raise ValueError("Data pesan pada gambar rusak atau tidak lengkap.")

    payload = _bits_to_bytes(next(bits) for _ in range(message_length * 8))
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Pesan tidak menggunakan format UTF-8 yang valid.") from error


class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stego LSB | Sisipkan dan Ekstrak Pesan")
        self.geometry("760x560")
        self.minsize(680, 500)
        self.image_path = tk.StringVar()
        self.capacity_text = tk.StringVar(value="Kapasitas: -")
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        root = ttk.Frame(self, padding=22)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="STEGANOGRAFI LSB", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(root, text="Sisipkan pesan ke dalam gambar atau ekstrak pesan tersembunyi.").pack(anchor="w", pady=(2, 18))

        image_frame = ttk.LabelFrame(root, text="Gambar", padding=12)
        image_frame.pack(fill="x", pady=(0, 14))
        ttk.Entry(image_frame, textvariable=self.image_path).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(image_frame, text="Pilih gambar", command=self.choose_image).pack(side="left")
        ttk.Label(image_frame, textvariable=self.capacity_text).pack(anchor="w", pady=(9, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        encode_tab = ttk.Frame(notebook, padding=16)
        decode_tab = ttk.Frame(notebook, padding=16)
        notebook.add(encode_tab, text="Sisipkan pesan")
        notebook.add(decode_tab, text="Ekstrak pesan")

        ttk.Label(encode_tab, text="Pesan rahasia").pack(anchor="w")
        self.message_box = tk.Text(encode_tab, height=12, wrap="word", font=("Segoe UI", 11), undo=True)
        self.message_box.pack(fill="both", expand=True, pady=(7, 12))
        ttk.Button(encode_tab, text="Sisipkan dan simpan PNG", command=self.encode).pack(anchor="e")

        ttk.Label(decode_tab, text="Pesan hasil ekstraksi").pack(anchor="w")
        self.extracted_box = tk.Text(decode_tab, height=12, wrap="word", font=("Segoe UI", 11), state="disabled")
        self.extracted_box.pack(fill="both", expand=True, pady=(7, 12))
        ttk.Button(decode_tab, text="Ekstrak pesan", command=self.decode).pack(anchor="e")

        ttk.Label(root, text="LSB diterapkan pada kanal R, G, dan B. Simpan hasil sebagai PNG agar bit tetap utuh.", foreground="#555555").pack(anchor="w", pady=(14, 0))

    def choose_image(self):
        path = filedialog.askopenfilename(
            title="Pilih gambar",
            filetypes=[("Gambar", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff"), ("Semua file", "*.*")],
        )
        if not path:
            return
        self.image_path.set(path)
        try:
            with Image.open(path) as image:
                self.capacity_text.set(f"Kapasitas pesan: {max_message_bytes(image):,} byte")
        except Exception as error:
            self.capacity_text.set("Kapasitas: -")
            messagebox.showerror("Gagal membuka gambar", str(error))

    def encode(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar terlebih dahulu.")
            return
        message = self.message_box.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Pesan kosong", "Masukkan pesan yang ingin disisipkan.")
            return
        output_path = filedialog.asksaveasfilename(
            title="Simpan gambar stego",
            defaultextension=".png",
            filetypes=[("PNG", "*.png")],
            initialfile=f"{Path(self.image_path.get()).stem}_stego.png",
        )
        if not output_path:
            return
        try:
            with Image.open(self.image_path.get()) as image:
                encoded = embed_message(image, message)
                encoded.save(output_path, "PNG")
            messagebox.showinfo("Berhasil", f"Pesan berhasil disisipkan ke:\n{output_path}")
        except Exception as error:
            messagebox.showerror("Gagal menyisipkan pesan", str(error))

    def decode(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar terlebih dahulu.")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                message = extract_message(image)
            self.extracted_box.configure(state="normal")
            self.extracted_box.delete("1.0", "end")
            self.extracted_box.insert("1.0", message)
            self.extracted_box.configure(state="disabled")
        except Exception as error:
            messagebox.showerror("Gagal mengekstrak pesan", str(error))


if __name__ == "__main__":
    SteganographyApp().mainloop()
