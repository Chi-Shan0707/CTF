import random
import time
from randcrack import RandCrack

def demo_randcrack():
    secret_seed = int(time.time())
    random.seed(secret_seed)
    print(f"[*] Target initialized with seed: {secret_seed}")

    rc = RandCrack()
    
    print("[*] Collecting 624 integers from the target...")
    
    for i in range(624):
        observed_value = random.getrandbits(32)
        rc.submit(observed_value)

    print("[+] State collection complete. Cracking the generator...")

    print("\n--- Verification ---")
    
    for i in range(1, 6):
        predicted_value = rc.predict_getrandbits(32)
        actual_value = random.getrandbits(32)
        
        if predicted_value == actual_value:
            print(f"[Success] Next output {i}: {predicted_value} (Matches!)")
        else:
            print(f"[Fail] Next output {i}: Predicted {predicted_value}, Actual {actual_value}")

    print("\n--- Predicting other types ---")
    pred_range = rc.predict_randrange(0, 1000)
    act_range = random.randrange(0, 1000)
    print(f"randrange(0, 1000) -> Predicted: {pred_range}, Actual: {act_range}")

if __name__ == '__main__':
    demo_randcrack()