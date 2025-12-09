from ultralytics import YOLO
import cv2

# Load the trained classification model
frisbee_classifier = YOLO("./runs_cls/frisbee_cls/weights/best.pt")

def detect_frisbee_in_webcam_frame(confidence_threshold=0.7):

    # Open webcam (device index 1)
    webcam = cv2.VideoCapture(1)

    if not webcam.isOpened():
        print("Error: Unable to access webcam.")
        return False

    # Capture a single frame
    frame_captured, frame = webcam.read()

    # Release webcam resource immediately after capturing
    webcam.release()

    if not frame_captured:
        print("Error: Failed to capture image from webcam.")
        return False

    # Run classification on the captured frame
    prediction_results = frisbee_classifier.predict(
        frame,
        imgsz=224,
        verbose=False
    )
    prediction = prediction_results[0]

    top_class_id = prediction.probs.top1
    top_class_confidence = float(prediction.probs.top1conf)
    top_class_name = prediction.names[top_class_id]

    print(f"Prediction: {top_class_name} ({top_class_confidence:.2f})")

    return (
        top_class_name.lower() == "frisbee"
        and top_class_confidence >= confidence_threshold
    )
