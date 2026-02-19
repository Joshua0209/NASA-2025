from PIL import Image
image_file = "secret_mygo.png"

# Open image
img = Image.open(image_file)

# Get pixels' values
pixels = list(img.getdata())

data = ""

for i in range(32):
    colors = list(pixels[i * 3]) + \
        list(pixels[i * 3 + 1]) + list(pixels[i * 3 + 2])

    binary = ""

    for j in range(8):
        b = "1" if colors[j] % 2 == 1 else "0"
        binary += b

    char = chr(int(binary, 2))
    data += char

print(data)
# HW12{S4KiCh4n_sakiCHAN_S4k1ChaN}
