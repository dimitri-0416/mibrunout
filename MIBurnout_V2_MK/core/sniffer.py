from queue import Queue
from scapy.all import sniff


class Sniffer(object):
	"""Sniffe le réseau sur une interface spécifiée et place les paquets dans une FILE"""
	def __init__(self, iface:str, sfilter:str, queue:Queue):
		self.iface = iface
		self.sfilter = sfilter
		self.queue = queue
		self.packet_lost = 0

	def send_to_queue(self, pkt):
		try:
			self.queue.put_nowait(pkt)
			print(f"[SNIFFER] Packet sent to queue (size={self.queue.qsize()})")
		except Exception:
			self.packet_lost += 1
			print(f"\n[!] File pleine — paquet ignoré ({self.packet_lost})")
	
	def afficher_trafic(self):
		while True:
			try:
				pkt = self.queue.get()
				self.queue.task_done()
				pkt.show()
			except KeyboardInterrupt:
				print("\n[!] Arrêt !!!")
				break

	def start_sniffer(self):
		try:
			print(f"[SNIFFER] Starting on interface '{self.iface}' with filter '{self.sfilter}'")
			sniff(iface=self.iface, filter=self.sfilter, prn=self.send_to_queue, store=False)
		except KeyboardInterrupt:
			print("\n[!] Arrêt !!!")
		except Exception as e:
			print(f"[SNIFFER ERROR] {e}")

if __name__ == "__main__":
	from threading import Thread

	print("[i] Lancement du Sniffer")
	
	q = Queue(maxsize=100)
	sniffer = Sniffer(iface="enp4s0", sfilter="udp port 161 or udp port 162", queue=q)
	
	thread_sniff = Thread(target=sniffer.start_sniffer, daemon=True)
	thread_sniff.start()

	try:
		sniffer.afficher_trafic()
	except KeyboardInterrupt:
		print("\n[!] Arrêt du programme.")