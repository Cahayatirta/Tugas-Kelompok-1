import io
import math
import struct
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import numpy as np
from PIL import Image

MAGIC = b"LSB1"
HEADER_SIZE = len(MAGIC) + 4
DCT_BLOCK_SIZE = 8
DCT_STRENGTH = 48.0
DCT_MATRIX = np.array(
    [
        [
            math.sqrt(1 / DCT_BLOCK_SIZE)
            if frequency == 0
            else math.sqrt(2 / DCT_BLOCK_SIZE)
            * math.cos((2 * position + 1) * frequency * math.pi / (2 * DCT_BLOCK_SIZE))
            for frequency in range(DCT_BLOCK_SIZE)
        ]
        for position in range(DCT_BLOCK_SIZE)
    ],
    dtype=np.float32,
)


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


def _dct_blocks(image: Image.Image):
    width, height = image.size
    for top in range(0, height - DCT_BLOCK_SIZE + 1, DCT_BLOCK_SIZE):
        for left in range(0, width - DCT_BLOCK_SIZE + 1, DCT_BLOCK_SIZE):
            yield left, top


def max_message_bytes(image: Image.Image, method: str = "LSB") -> int:
    rgb = image.convert("RGB")
    if method == "DCT":
        available_bits = (rgb.width // DCT_BLOCK_SIZE) * (rgb.height // DCT_BLOCK_SIZE)
        return max(0, (available_bits - HEADER_SIZE * 8) // 8)
    return max(0, (rgb.width * rgb.height * 3 - HEADER_SIZE * 8) // 8)


def _packet(message: str) -> bytes:
    payload = message.encode("utf-8")
    return MAGIC + struct.pack(">I", len(payload)) + payload


def _embed_dct(image: Image.Image, packet: bytes) -> Image.Image:
    ycbcr = image.convert("YCbCr")
    luminance, chroma_blue, chroma_red = ycbcr.split()
    pixels = np.asarray(luminance, dtype=np.float32).copy()
    bits = iter(_bytes_to_bits(packet))

    for left, top in _dct_blocks(image):
        try:
            bit = next(bits)
        except StopIteration:
            break
        block = pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE]
        coefficients = DCT_MATRIX @ block @ DCT_MATRIX.T
        first = coefficients[3, 2]
        second = coefficients[2, 3]
        middle = (first + second) / 2
        target_difference = DCT_STRENGTH if bit else -DCT_STRENGTH
        coefficients[3, 2] = middle + target_difference / 2
        coefficients[2, 3] = middle - target_difference / 2
        pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE] = (
            DCT_MATRIX.T @ coefficients @ DCT_MATRIX
        )

    luminance = Image.fromarray(np.clip(pixels, 0, 255).astype(np.uint8))
    return Image.merge("YCbCr", (luminance, chroma_blue, chroma_red)).convert("RGB")


def embed_message(image: Image.Image, message: str, method: str = "LSB") -> Image.Image:
    rgb = image.convert("RGB")
    packet = _packet(message)
    capacity = max_message_bytes(rgb, method)
    if len(packet) - HEADER_SIZE > capacity:
        raise ValueError(
            f"Pesan terlalu besar. Kapasitas gambar hanya {capacity:,} byte."
        )
    if method == "DCT":
        return _embed_dct(rgb, packet)
    if method != "LSB":
        raise ValueError("Metode steganografi tidak dikenal.")

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


def _read_bits(image: Image.Image, method: str, bit_count: int):
    if method == "LSB":
        channels = (channel & 1 for pixel in image.convert("RGB").getdata() for channel in pixel)
        return [bit for _, bit in zip(range(bit_count), channels)]
    if method != "DCT":
        raise ValueError("Metode steganografi tidak dikenal.")

    y_channel = image.convert("YCbCr").getchannel(0)
    pixels = np.asarray(y_channel, dtype=np.float32)
    bits = []
    for left, top in _dct_blocks(image):
        if len(bits) >= bit_count:
            break
        block = pixels[top : top + DCT_BLOCK_SIZE, left : left + DCT_BLOCK_SIZE]
        coefficients = DCT_MATRIX @ block @ DCT_MATRIX.T
        bits.append(int(coefficients[3, 2] >= coefficients[2, 3]))
    return bits


def extract_message(image: Image.Image, method: str = "LSB") -> str:
    rgb = image.convert("RGB")
    header_bits = _read_bits(rgb, method, HEADER_SIZE * 8)
    if len(header_bits) < HEADER_SIZE * 8:
        raise ValueError("Gambar terlalu kecil untuk memuat header pesan.")
    header = _bits_to_bytes(header_bits)
    if header[: len(MAGIC)] != MAGIC:
        raise ValueError(f"Gambar tidak memiliki pesan {method} yang valid.")

    message_length = struct.unpack(">I", header[len(MAGIC) :])[0]
    available = (
        rgb.width // DCT_BLOCK_SIZE * (rgb.height // DCT_BLOCK_SIZE)
        if method == "DCT"
        else rgb.width * rgb.height * 3
    ) - HEADER_SIZE * 8
    if message_length * 8 > available:
        raise ValueError("Data pesan pada gambar rusak atau tidak lengkap.")

    all_bits = _read_bits(rgb, method, HEADER_SIZE * 8 + message_length * 8)
    payload = _bits_to_bytes(all_bits[HEADER_SIZE * 8 :])
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Pesan tidak menggunakan format UTF-8 yang valid.") from error


def calculate_ber(image: Image.Image, message: str, method: str) -> float:
    expected_bits = list(_bytes_to_bits(message.encode("utf-8")))
    if not expected_bits:
        raise ValueError("Pesan tidak boleh kosong saat menghitung BER.")
    encoded_bits = _read_bits(image, method, HEADER_SIZE * 8 + len(expected_bits))
    actual_bits = encoded_bits[HEADER_SIZE * 8 :]
    errors = sum(actual != expected for actual, expected in zip(actual_bits, expected_bits))
    errors += len(expected_bits) - len(actual_bits)
    return errors / len(expected_bits)


def apply_attack(image: Image.Image, quality: int = 50) -> Image.Image:
    if not 1 <= quality <= 100:
        raise ValueError("Kualitas JPEG harus antara 1 sampai 100%.")
    rgb = image.convert("RGB")
    output = io.BytesIO()
    rgb.save(output, format="JPEG", quality=quality)
    output.seek(0)
    with Image.open(output) as compressed:
        return compressed.convert("RGB").copy()


class SteganographyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Steganografi | LSB dan DCT")
        self.geometry("900x700")
        self.minsize(620, 440)
        self.image_path = tk.StringVar()
        self.method = tk.StringVar(value="LSB")
        self.jpeg_quality = tk.IntVar(value=50)
        self.capacity_text = tk.StringVar(value="Kapasitas: -")
        self.ber_text = tk.StringVar(value="BER: -")
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        viewport = ttk.Frame(self)
        viewport.pack(fill="both", expand=True)
        canvas = tk.Canvas(viewport, highlightthickness=0)
        scrollbar = ttk.Scrollbar(viewport, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        root = ttk.Frame(canvas, padding=16)
        content_window = canvas.create_window((0, 0), window=root, anchor="nw")
        root.bind("<Configure>", lambda _event: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda event: canvas.itemconfigure(content_window, width=event.width))
        canvas.bind_all("<MouseWheel>", lambda event: canvas.yview_scroll(-1 * (event.delta // 120), "units"))
        ttk.Label(root, text="STEGANOGRAFI", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(root, text="Sisipkan, ekstrak, dan uji ketahanan pesan.").pack(anchor="w", pady=(2, 12))

        image_frame = ttk.LabelFrame(root, text="Gambar", padding=12)
        image_frame.pack(fill="x", pady=(0, 10))
        image_row = ttk.Frame(image_frame)
        image_row.pack(fill="x")
        ttk.Entry(image_row, textvariable=self.image_path).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(image_row, text="Pilih gambar", command=self.choose_image).pack(side="left")
        ttk.Label(image_row, text="Metode").pack(side="left", padx=(12, 5))
        method_select = ttk.Combobox(image_row, textvariable=self.method, values=("LSB", "DCT"), state="readonly", width=8)
        method_select.pack(side="left")
        method_select.bind("<<ComboboxSelected>>", self.update_capacity)
        ttk.Label(image_frame, textvariable=self.capacity_text).pack(anchor="w", pady=(8, 0))

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True)

        encode_tab = ttk.Frame(notebook, padding=16)
        decode_tab = ttk.Frame(notebook, padding=16)
        attack_tab = ttk.Frame(notebook, padding=16)
        notebook.add(encode_tab, text="Sisipkan pesan")
        notebook.add(decode_tab, text="Ekstrak pesan")
        notebook.add(attack_tab, text="Uji serangan dan BER")

        ttk.Label(encode_tab, text="Pesan rahasia").pack(anchor="w")
        self.message_box = tk.Text(encode_tab, height=12, wrap="word", font=("Segoe UI", 11), undo=True)
        self.message_box.pack(fill="both", expand=True, pady=(7, 12))
        ttk.Button(encode_tab, text="Sisipkan dan simpan PNG", command=self.encode).pack(anchor="e")

        ttk.Label(decode_tab, text="Pesan hasil ekstraksi").pack(anchor="w")
        self.extracted_box = tk.Text(decode_tab, height=12, wrap="word", font=("Segoe UI", 11), state="disabled")
        self.extracted_box.pack(fill="both", expand=True, pady=(7, 12))
        ttk.Button(decode_tab, text="Ekstrak pesan", command=self.decode).pack(anchor="e")

        ttk.Label(attack_tab, text="Uji BER setelah kompresi JPEG pada gambar stego yang dipilih.").pack(anchor="w")
        ttk.Label(attack_tab, text="Kualitas kompresi JPEG (%)").pack(anchor="w", pady=(16, 4))
        ttk.Spinbox(
            attack_tab,
            from_=1,
            to=100,
            increment=1,
            textvariable=self.jpeg_quality,
            width=8,
        ).pack(anchor="w")
        ttk.Button(attack_tab, text="Jalankan uji BER", command=self.test_attack).pack(anchor="w", pady=(14, 8))
        ttk.Label(attack_tab, textvariable=self.ber_text, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(
            attack_tab,
            text="BER = jumlah bit pesan yang salah atau hilang dibagi jumlah bit pesan.",
            foreground="#555555",
        ).pack(anchor="w", pady=(8, 0))

    def choose_image(self):
        path = filedialog.askopenfilename(
            title="Pilih gambar",
            filetypes=[("Gambar", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff"), ("Semua file", "*.*")],
        )
        if not path:
            return
        self.image_path.set(path)
        self.update_capacity()

    def update_capacity(self, _event=None):
        if not self.image_path.get():
            self.capacity_text.set("Kapasitas: -")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                method = self.method.get()
                self.capacity_text.set(f"Kapasitas {method}: {max_message_bytes(image, method):,} byte")
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
                encoded = embed_message(image, message, self.method.get())
                encoded.save(output_path, "PNG")
            self.image_path.set(output_path)
            self.update_capacity()
            messagebox.showinfo("Berhasil", f"Pesan berhasil disisipkan ke:\n{output_path}")
        except Exception as error:
            messagebox.showerror("Gagal menyisipkan pesan", str(error))

    def decode(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar terlebih dahulu.")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                message = extract_message(image, self.method.get())
            self.extracted_box.configure(state="normal")
            self.extracted_box.delete("1.0", "end")
            self.extracted_box.insert("1.0", message)
            self.extracted_box.configure(state="disabled")
        except Exception as error:
            messagebox.showerror("Gagal mengekstrak pesan", str(error))

    def test_attack(self):
        if not self.image_path.get():
            messagebox.showwarning("Gambar belum dipilih", "Pilih gambar stego terlebih dahulu.")
            return
        message = self.message_box.get("1.0", "end-1c")
        if not message:
            messagebox.showwarning("Pesan kosong", "Masukkan pesan asli pada tab sisipkan terlebih dahulu.")
            return
        try:
            with Image.open(self.image_path.get()) as image:
                quality = self.jpeg_quality.get()
                attacked = apply_attack(image, quality)
            ber = calculate_ber(attacked, message, self.method.get())
            self.ber_text.set(f"BER setelah JPEG kualitas {quality}%: {ber:.6f} ({ber * 100:.2f}%)")
        except Exception as error:
            messagebox.showerror("Gagal menguji serangan", str(error))


if __name__ == "__main__":
    SteganographyApp().mainloop()
