from scapy.all import sniff, conf
def process(p):
    print(p.summary())
try:
    print("Trying default...")
    sniff(count=2, prn=process, timeout=2)
except Exception as e:
    print("Default failed:", e)
    try:
        print("Trying L3socket...")
        sniff(count=2, prn=process, L2socket=conf.L3socket, timeout=2)
    except Exception as e2:
        print("L3socket failed:", e2)
