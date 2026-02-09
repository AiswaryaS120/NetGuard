import unittest
from unittest.mock import MagicMock
import queue
from network_engine import SnifferThread
from ml_engine import AnomalyDetector
import time

class TestSystemIntegration(unittest.TestCase):
    def test_feature_shape(self):
        print("\nTesting Feature Extraction Shape...")
        q = queue.Queue()
        sniffer = SnifferThread(q)
        
        # Mock a packet info dict (simulating scapy packet parsing)
        packet_info = {
            'src_ip': '192.168.1.5',
            'dst_ip': '10.0.0.1',
            'src_port': 12345,
            'dst_port': 80,
            'protocol': 6,
            'length': 60,
            'flag': 'SF'
        }
        
        features = sniffer.monitor.update_and_get_features(packet_info)
        print(f"Extracted Features: {features}")
        
        self.assertEqual(len(features), 14, "Feature vector must have length 14")
        print("PASS: Feature shape is correct.")

    def test_model_prediction(self):
        print("\nTesting Model Prediction...")
        detector = AnomalyDetector(model_path='rf_model.pkl')
        
        if not detector.model:
            print("WARNING: Model not found, skipping prediction test.")
            return

        # Create a dummy feature vector of length 14
        dummy_features = [0, 60, 0, 1, 1, 1.0, 0.0, 1, 1, 1.0, 0.0, 1.0, 0.0, 0.0]
        
        feature_dict = {'ml_features': dummy_features}
        prediction = detector.predict(feature_dict)
        
        print(f"Prediction result: {prediction}")
        # Updated to check for string labels (e.g., 'normal', 'DoS Attack')
        self.assertIsInstance(prediction, str, "Prediction must be a string label")
        self.assertTrue(len(prediction) > 0, "Prediction string should not be empty")
        print("PASS: Model prediction successful.")

if __name__ == '__main__':
    unittest.main()
