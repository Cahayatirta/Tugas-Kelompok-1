import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import numpy as np
from PIL import Image, ImageTk
from skimage.metrics import structural_similarity


def load_rgb(path):
    with Image.open(path) as image:
        return image.convert("RGB").copy()


def calculate_metrics(original: Image.Image, compared: Image.Image):
    if original.size != compared.size:
        compared = compared.resize(original.size, Image.Resampling.LANCZOS)
    original_array = np.asarray(original, dtype=np.float64)
    compared_array = np.asarray(compared, dtype=np.float64)
    difference = original_array - compared_array
    mse = float(np.mean(difference ** 2))
    if mse == 0:
        psnr = float("inf")
    else:
        psnr = float(10 * np.log10((255.0 ** 2) / mse))
    ssim = float(
        structural_similarity(
            original_array.astype(np.uint8),
            compared_array.astype(np.uint8),
            channel_axis=2,
            data_range=255,
        )
    )
    return mse, psnr, ssim


class MetricsApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Analisis Citra | MSE, PSNR, SSIM")
        self.geometry("820x600")
        self.minsize(720, 520)
        self.original_path = tk.StringVar()
        self.compared_path = tk.StringVar()
        self.original_preview = None
        self.compared_preview = None
        self._build_ui()

    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        root = ttk.Frame(self, padding=22)
        root.pack(fill="both", expand=True)
        ttk.Label(root, text="ANALISIS KUALITAS CITRA", font=("Segoe UI", 19, "bold")).pack(anchor="w")
        ttk.Label(root, text="Bandingkan gambar asli dengan gambar hasil steganografi.").pack(anchor="w", pady=(2, 18))

        paths = ttk.LabelFrame(root, text="Pilih citra", padding=12)
        paths.pack(fill="x", pady=(0, 14))
        self._path_row(paths, "Citra asli", self.original_path, self.choose_original)
        self._path_row(paths, "Citra hasil", self.compared_path, self.choose_compared)

        preview = ttk.Frame(root)
        preview.pack(fill="both", expand=True)
        left = ttk.LabelFrame(preview, text="Asli", padding=8)
        left.pack(side="left", fill="both", expand=True, padx=(0, 6))
        right = ttk.LabelFrame(preview, text="Hasil", padding=8)
        right.pack(side="left", fill="both", expand=True, padx=(6, 0))
        self.original_label = ttk.Label(left, text="Belum ada gambar", anchor="center")
        self.original_label.pack(fill="both", expand=True)
        self.compared_label = ttk.Label(right, text="Belum ada gambar", anchor="center")
        self.compared_label.pack(fill="both", expand=True)

        ttk.Button(root, text="Hitung MSE, PSNR, dan SSIM", command=self.calculate).pack(anchor="e", pady=14)
        result = ttk.LabelFrame(root, text="Hasil pengukuran", padding=14)
        result.pack(fill="x")
        self.mse_value = ttk.Label(result, text="MSE  -", font=("Segoe UI", 12, "bold"))
        self.psnr_value = ttk.Label(result, text="PSNR  -", font=("Segoe UI", 12, "bold"))
        self.ssim_value = ttk.Label(result, text="SSIM  -", font=("Segoe UI", 12, "bold"))
        self.mse_value.grid(row=0, column=0, sticky="w", padx=(0, 42))
        self.psnr_value.grid(row=0, column=1, sticky="w", padx=(0, 42))
        self.ssim_value.grid(row=0, column=2, sticky="w")

    def _path_row(self, parent, label, variable, command):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=4)
        ttk.Label(row, text=label, width=13).pack(side="left")
        ttk.Entry(row, textvariable=variable).pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(row, text="Pilih", command=command).pack(side="left")

    def _choose(self, variable, label_widget):
        path = filedialog.askopenfilename(
            title="Pilih gambar",
            filetypes=[("Gambar", "*.png *.jpg *.jpeg *.bmp *.tif *.tiff"), ("Semua file", "*.*")],
        )
        if not path:
            return
        variable.set(path)
        try:
            image = load_rgb(path)
            image.thumbnail((360, 240), Image.Resampling.LANCZOS)
            preview = ImageTk.PhotoImage(image)
            label_widget.configure(image=preview, text="")
            return preview
        except Exception as error:
            messagebox.showerror("Gagal membuka gambar", str(error))
            return None

    def choose_original(self):
        self.original_preview = self._choose(self.original_path, self.original_label)

    def choose_compared(self):
        self.compared_preview = self._choose(self.compared_path, self.compared_label)

    def calculate(self):
        if not self.original_path.get() or not self.compared_path.get():
            messagebox.showwarning("Citra belum lengkap", "Pilih citra asli dan citra hasil terlebih dahulu.")
            return
        try:
            original = load_rgb(self.original_path.get())
            compared = load_rgb(self.compared_path.get())
            mse, psnr, ssim = calculate_metrics(original, compared)
            self.mse_value.configure(text=f"MSE  {mse:.6f}")
            self.psnr_value.configure(text=f"PSNR  {'infinity' if np.isinf(psnr) else f'{psnr:.4f}'} dB")
            self.ssim_value.configure(text=f"SSIM  {ssim:.6f}")
        except Exception as error:
            messagebox.showerror("Gagal menghitung metrik", str(error))


if __name__ == "__main__":
    MetricsApp().mainloop()
