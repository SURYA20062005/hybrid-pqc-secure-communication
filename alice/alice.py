from flask import Flask, render_template, request, jsonify
import serial
import threading
import time

app = Flask(__name__)

SERIAL_PORT = "COM8"   # Change to Alice ESP32 COM port
BAUD_RATE = 115200

esp32 = None
lock = threading.Lock()

state = {
    "public_key": "-",
    "shared_secret": "-",
    "aes_key": "-",
    "nonce": "-",
    "ciphertext": "-",
    "tag": "-",
    "sent_message": "-",
    "logs": []
}


def add_log(message):
    with lock:
        timestamp = time.strftime("%H:%M:%S")
        state["logs"].append(f"[{timestamp}] ALICE: {message}")
        state["logs"] = state["logs"][-300:]


def process_line(line):
    line = line.strip()

    if not line:
        return

    add_log(line)

    with lock:
        if line.startswith("DEBUG_PUBLIC_KEY:"):
            state["public_key"] = line.split(":", 1)[1].strip()

        elif line.startswith("DEBUG_SHARED_SECRET:"):
            state["shared_secret"] = line.split(":", 1)[1].strip()

        elif line.startswith("DEBUG_AES_KEY:"):
            state["aes_key"] = line.split(":", 1)[1].strip()

        elif line.startswith("DEBUG_NONCE:"):
            state["nonce"] = line.split(":", 1)[1].strip()

        elif line.startswith("DEBUG_CIPHERTEXT:"):
            state["ciphertext"] = line.split(":", 1)[1].strip()

        elif line.startswith("DEBUG_TAG:"):
            state["tag"] = line.split(":", 1)[1].strip()

        elif line.startswith("SENT_MESSAGE:"):
            state["sent_message"] = line.split(":", 1)[1].strip()


def serial_reader():
    while True:
        try:
            if esp32 is not None and esp32.in_waiting:
                line = esp32.readline().decode(
                    "utf-8",
                    errors="ignore"
                )
                process_line(line)
            else:
                time.sleep(0.01)

        except Exception as error:
            add_log(f"Serial reader error: {error}")
            time.sleep(1)


def send_command(command):
    if esp32 is None:
        add_log("Alice ESP32 is not connected")
        return False

    try:
        esp32.write((command + "\n").encode("utf-8"))
        esp32.flush()
        add_log(f"Command sent: {command}")
        return True

    except Exception as error:
        add_log(f"Command error: {error}")
        return False


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/status")
def status():
    with lock:
        return jsonify(state)


@app.route("/command", methods=["POST"])
def command():
    data = request.get_json(silent=True) or {}
    value = data.get("command", "")
    return jsonify({"success": send_command(value)})


@app.route("/send_message", methods=["POST"])
def send_message():
    data = request.get_json(silent=True) or {}
    message = data.get("message", "").strip()

    if not message:
        return jsonify({
            "success": False,
            "error": "Message is empty"
        })

    return jsonify({
        "success": send_command("SEND_MESSAGE:" + message)
    })


@app.route("/clear", methods=["POST"])
def clear():
    with lock:
        state["public_key"] = "-"
        state["shared_secret"] = "-"
        state["aes_key"] = "-"
        state["nonce"] = "-"
        state["ciphertext"] = "-"
        state["tag"] = "-"
        state["sent_message"] = "-"
        state["logs"].clear()

    return jsonify({"success": True})


if __name__ == "__main__":
    try:
        esp32 = serial.Serial(
            SERIAL_PORT,
            BAUD_RATE,
            timeout=0.1
        )

        time.sleep(2)

        threading.Thread(
            target=serial_reader,
            daemon=True
        ).start()

        print("Alice ESP32 connected on", SERIAL_PORT)

        app.run(
            host="127.0.0.1",
            port=5000,
            debug=False
        )

    except Exception as error:
        print("Could not connect to Alice ESP32:", error)