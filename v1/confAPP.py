import json
import os

class ConfAPP(object):
	"""Gestionnaire de configuration de l'application (I/O uniquement)."""
	def __init__(self, confFile:str="conf.json"):
		self.confFile = confFile
		self.config = None
		self.load_config()

	def load_config(self):
		"""Charge la configuration depuis le fichier."""
		if os.path.exists(self.confFile):
			try:
				with open(self.confFile, "r", encoding="utf-8") as file:
					self.config = json.load(file)
			except json.JSONDecodeError as e:
				print(f"Erreur de lecture du JSON : {e}")
				self.config = None
		else:
			self.config = None
	
	def creatConf(self):
		default_conf = {
			"filtres":{},
			"whiteList":{
				"MACs":[],
				"IPs":[],
				"PORTs":[],
				"OIDs":[]
			}
		}
		try:
			with open(self.confFile, "w", encoding="utf-8") as f:
				json.dump(default_conf, f, indent=4, ensure_ascii=False)
			self.config = default_conf
		except Exception as e:
			print(f"Erreur lors de la génération du fichier : {e}")

	def afficherConf(self, motClef: str = None):
		if self.config is None:
			print("Aucune configuration chargée.")
			return 1

		if motClef is None:
			print(json.dumps(self.config, indent=4))
		else:
			resultats = self.rechercher_clef(motClef)
			if resultats:
				for chemin, valeur in resultats:
					print(f"{chemin}: {valeur}")
			else:
				print(f"Aucune clé '{motClef}' trouvée.")

	def rechercher_clef(self, clef, dico=None, chemin_actuel=""):
		if dico is None:
			dico = self.config
		if dico is None:
			return []

		resultats = []
		for key, value in dico.items():
			nouveau_chemin = f"{chemin_actuel}/{key}" if chemin_actuel else key
			if key == clef:
				resultats.append((nouveau_chemin, value))
			elif isinstance(value, dict):
				resultats.extend(self.rechercher_clef(clef, value, nouveau_chemin))
		return resultats

	def addRule(self, rule:dict, path:str = "filtres"):
		if self.config is None:
			print("Configuration non chargée.")
			return 1

		section = self.config
		for part in path.split("/"):
			if part not in section or not isinstance(section[part], dict):
				print(f"Section '{path}' introuvable.")
				return 1
		
		section.update(rule)
		self._save()
		print(f"Règle ajoutée à '{path}'.")
		return 0

	def delRule(self, path: str):
		if self.config is None: return 1
		parts = path.split("/")
		if len(parts) < 1: return 1

		section = self.config
		for part in parts[:-1]:
			if part not in section or not isinstance(section[part], dict):
				return 1
			section = section[part]

		rule = parts[-1]
		if rule not in section: return 1
		
		del section[rule]
		self._save()
		print(f"Clé '{rule}' supprimée.")
		return 0

	def _save(self):
		try:
			with open(self.confFile, "w", encoding="utf-8") as f:
				json.dump(self.config, f, indent=4, ensure_ascii=False)
		except Exception as e:
			print(f"Erreur sauvegarde : {e}")

if __name__ == "__main__":
	print("\n--- [TEST] Démarrage des tests de ConfAPP ---")
	test_file = "conf_test.json"
	# Nettoyage préventif
	if os.path.exists(test_file): os.remove(test_file)
	
	c = ConfAPP(test_file)
	print(f"\n[i] Création conf dans {test_file}")
	c.creatConf()

	print("\n[i] Ajout règle")
	r = {"rule_test": {"ip_src": "1.1.1.1"}}
	c.addRule(r, "filtres")
	c.afficherConf("rule_test")

	print("\n[i] Suppression règle")
	c.delRule("filtres/rule_test")
	
	# Nettoyage final
	if os.path.exists(test_file): os.remove(test_file)
	print("\n[i] Fin des tests ConfAPP.")