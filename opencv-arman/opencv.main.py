
"""

import cv2

# Resmin yolunu belirtin
resim_yolu = 'kopekler.jpg'  # Burada 'kopek.jpg' dosya adını ve yolunu doğru yazdığınızdan emin olun

# Resmi oku
image = cv2.imread(resim_yolu)

# Resmi gri tonlamalı hale getir
gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

# Siyah-beyaz resmi kaydet
cv2.imwrite('kopek_siyah_beyaz.jpg', gray_image)

# Sonucu göster
cv2.imshow('WIN', gray_image)
cv2.waitKey(0)  # Pencerenin açık kalmasını sağlar
cv2.destroyAllWindows()  # Pencereyi kapatır

"""





"""

import cv2


cap = cv2.VideoCapture(0)

ret, frame1 = cap.read()
gray1 = cv2.cvtColor(frame1, cv2.COLOR_BGR2GRAY)
gray1 = cv2.GaussianBlur(gray1, (21, 21), 0)

while True:
    
    ret, frame2 = cap.read()
    if not ret:
        break

    
    gray2 = cv2.cvtColor(frame2, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.GaussianBlur(gray2, (21, 21), 0)

    
    delta_frame = cv2.absdiff(gray1, gray2)

    
    thresh = cv2.threshold(delta_frame, 25, 255, cv2.THRESH_BINARY)[1]

    
    contours, _ = cv2.findContours(thresh.copy(), cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

    
    for contour in contours:
        if cv2.contourArea(contour) < 1000:  
            continue
        (x, y, w, h) = cv2.boundingRect(contour)
        cv2.rectangle(frame2, (x, y), (x+w, y+h), (0, 255, 0), 2)

    
    cv2.imshow("Frame", frame2)

    
    if cv2.waitKey(1) & 0xFF == ord('q'):
        break

    
    gray1 = gray2.copy()


cap.release()
cv2.destroyAllWindows()


import cv2
import mediapipe as mp


mp_hands = mp.solutions.hands
mp_drawing = mp.solutions.drawing_utils


hands = mp_hands.Hands()


cap = cv2.VideoCapture(0)  

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    
    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    
    results = hands.process(rgb_frame)

    
    if results.multi_hand_landmarks:
        for hand_landmarks in results.multi_hand_landmarks:
            
            mp_drawing.draw_landmarks(frame, hand_landmarks, mp_hands.HAND_CONNECTIONS)


    cv2.imshow('El Tanima', frame)

    if cv2.waitKey(1) & 0xFF == 27:  
        break

cap.release()
cv2.destroyAllWindows()
"""



import cv2
import mediapipe as mp


mp_hands = mp.solutions.hands
mp_drawing = mp.solutions.drawing_utils


hands = mp_hands.Hands(max_num_hands=2)  

cap = cv2.VideoCapture(0)  

def count_fingers(landmarks):
    
    fingers = []
    
    
    thumb_up = landmarks[mp_hands.HandLandmark.THUMB_TIP].y < landmarks[mp_hands.HandLandmark.THUMB_IP].y
    fingers.append(thumb_up)
    
    
    for finger_tip in [mp_hands.HandLandmark.INDEX_FINGER_TIP, mp_hands.HandLandmark.MIDDLE_FINGER_TIP, 
                       mp_hands.HandLandmark.RING_FINGER_TIP, mp_hands.HandLandmark.PINKY_TIP]:
        finger_base = landmarks[finger_tip].y
        finger_mid = landmarks[finger_tip - 2].y
        finger_fold = finger_base < finger_mid
        fingers.append(finger_fold)
    
    return fingers.count(True)

while cap.isOpened():
    ret, frame = cap.read()
    if not ret:
        break

    
    rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    
    results = hands.process(rgb_frame)

    
    total_fingers = 0
    if results.multi_hand_landmarks:
        for hand_landmarks in results.multi_hand_landmarks:
            
            mp_drawing.draw_landmarks(frame, hand_landmarks, mp_hands.HAND_CONNECTIONS)
            
            
            fingers_up = count_fingers(hand_landmarks.landmark)
            total_fingers += fingers_up

    
    cv2.putText(frame, f'Toplam Parmak Sayisi: {total_fingers}', (10, 30), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 255, 0), 2, cv2.LINE_AA)

    
    cv2.imshow('El Tanıma', frame)

    if cv2.waitKey(1) & 0xFF == 27:  
        break

cap.release()
cv2.destroyAllWindows()
