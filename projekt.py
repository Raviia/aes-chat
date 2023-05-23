import tkinter as tk
import tkinter.scrolledtext as scrolledtext
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import paho.mqtt.client as mqtt

# Stałe
BROKER = 'test.mosquitto.org'
TOPIC = 'Projekt Czat'
KEY = b'w1k4r3kl3n4rc1k!'
IV = b'G0rz4lcz4nySUM1!'

# Inicjalizacja klienta MQTT
client = mqtt.Client()

# Zmienna przechowująca nick
nickname = None

# Funkcja szyfrująca wiadomość
def encrypt_message(nickname, message):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    nickname = pad(nickname.encode('utf-8'), AES.block_size)
    message = pad(message.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(nickname + message)
    return ciphertext

# Funkcja deszyfrująca wiadomość
def decrypt_message(ciphertext):
    cipher = AES.new(KEY, AES.MODE_CBC, iv=IV)
    plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(plaintext, AES.block_size)
    nickname = plaintext[:AES.block_size].decode('utf-8').strip()
    message = plaintext[AES.block_size:].decode('utf-8')
    return nickname, message

# Funkcja obsługująca otrzymanie wiadomości
def on_message(client, userdata, message):
    nickname, plaintext = decrypt_message(message.payload)
    text_area.insert(tk.END, f"[{nickname}]: {plaintext}\n")

# Funkcja obsługująca wysyłanie wiadomości
def send_message():
    message = input_text.get('1.0', tk.END).strip()
    if message:
        ciphertext = encrypt_message(nickname, message)
        client.publish(TOPIC, ciphertext)
        input_text.delete('1.0', tk.END)

# Funkcja obsługująca zamykanie okna
def close_window():
    client.loop_stop()
    client.disconnect()
    root.destroy()

# Funkcja obsługująca podanie nicku
def set_nickname():
    global nickname
    nickname = nickname_entry.get().strip()
    if nickname:
        nickname_window.destroy()
        root.deiconify()
        root.title(f"AES Chat - {nickname}")

        # Podłączenie klienta MQTT
        client.on_message = on_message
        client.connect(BROKER, 1883)
        client.subscribe(TOPIC)
        client.loop_start()

# Funkcja zapisu do pliku
def save_messages():
    messages = text_area.get('1.0', tk.END).strip()
    if messages:
        ciphertexts = []
        for message in messages.split('\n'):
            ciphertext = encrypt_message(nickname, message)
            ciphertexts.append(ciphertext)
        
        with open("secret.txt", 'wb') as file:
            for ciphertext in ciphertexts:
                file.write(ciphertext)
                file.write(b'\n')

# Okno do podania nicku
nickname_window = tk.Tk()
nickname_window.title("Podaj nick")

nickname_label = tk.Label(nickname_window, text="Nick:")
nickname_label.pack()

nickname_entry = tk.Entry(nickname_window)
nickname_entry.pack()

nickname_button = tk.Button(nickname_window, text="OK", command=set_nickname)
nickname_button.pack()

# Okno główne
root = tk.Tk()
root.title("AES Chat")
root.withdraw()

text_area = scrolledtext.ScrolledText(root, height=20, width=50)
text_area.pack(padx=10, pady=10)

input_text = tk.Text(root, height=5, width=50)
input_text.pack(padx=10, pady=10)

send_button = tk.Button(root, text="Wyślij", command=send_message)
send_button.pack(padx=10, pady=10)

save_button = tk.Button(root, text="Zapisz", command=save_messages)
save_button.pack(padx=10, pady=10)

# Ustalenie funkcji, która zostanie wywołana przy zamknięciu okna
root.protocol("WM_DELETE_WINDOW", close_window)

root.mainloop()
