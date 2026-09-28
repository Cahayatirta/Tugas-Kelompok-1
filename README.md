# Aplikasi Steganografi dan Analisis Citra

## Instalasi

```powershell
python -m pip install -r requirements.txt
```

## Menjalankan aplikasi

```powershell
python app_steganografi/app.py
python app_metrics/app.py
```

Aplikasi steganografi menggunakan LSB pada kanal RGB dan menyimpan hasil dalam PNG. Aplikasi analisis membandingkan citra asli dan citra hasil untuk menghitung MSE, PSNR, dan SSIM.
