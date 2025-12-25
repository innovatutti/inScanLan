"""
Script per convertire logo_inscanlan.jpg in .ico per l'icona Windows
"""

from PIL import Image
import os

def convert_jpg_to_ico():
    try:
        # Apri l'immagine JPG
        img = Image.open('logo_inscanlan.jpg')
        
        # Converti in RGBA se necessario
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Crea diverse dimensioni per il file .ico
        icon_sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
        
        # Salva come .ico
        img.save('logo_inscanlan.ico', format='ICO', sizes=icon_sizes)
        
        print("✅ Conversione completata!")
        print("   File creato: logo_inscanlan.ico")
        
    except Exception as e:
        print(f"❌ Errore durante la conversione: {str(e)}")
        print("\nInstalla Pillow con: pip install pillow")

if __name__ == "__main__":
    print("🔄 Conversione logo_inscanlan.jpg -> logo_inscanlan.ico")
    print()
    convert_jpg_to_ico()
