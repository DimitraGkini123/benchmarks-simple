import serial
import csv

# Ρυθμίσεις
SERIAL_PORT = 'COM7'
BAUD_RATE = 115200 # Η default ταχύτητα του Pico
OUTPUT_FILE = 'pico_data_device2.csv'

try:
    # Άνοιγμα της σειριακής θύρας
    ser = serial.Serial(SERIAL_PORT, BAUD_RATE, timeout=1)
    print(f"Σύνδεση στο {SERIAL_PORT} επιτυχής. Ξεκινάει η καταγραφή...")

    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)
        
        while True:
            if ser.in_waiting > 0:
                # Διάβασμα γραμμής από τον Pico
                line = ser.readline().decode('utf-8').strip()
                
                if line:
                    print(line) # Εμφάνιση στο τερματικό για έλεγχο
                    
                    # Αν η γραμμή περιέχει "DONE", σταμάτα την καταγραφή
                    if "DONE" in line:
                        print("Η συλλογή ολοκληρώθηκε!")
                        break
                    
                    # Διαχωρισμός των τιμών με βάση το κόμμα και αποθήκευση
                    data = line.split(',')
                    writer.writerow(data)

except serial.SerialException as e:
    print(f"Σφάλμα σύνδεσης: {e}")
except KeyboardInterrupt:
    print("\nΗ καταγραφή διακόπηκε από τον χρήστη.")
finally:
    if 'ser' in locals() and ser.is_open:
        ser.close()
        print("Η σειριακή θύρα έκλεισε.")