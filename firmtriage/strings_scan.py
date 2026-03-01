'''
Inputs
	•	data: bytes
	•	config like min_len=4, max_results=200

Outputs (dict)
	•	count_total
	•	top_samples (list of strings)
	•	hits (categorized interesting strings)
	•	urls
	•	ips
	•	file_paths
	•	crypto_markers (e.g., “BEGIN CERTIFICATE”, “ssh-rsa”, “ed25519”)
	•	debug_markers (e.g., “JTAG”, “UART”, “console”, “debug”, “panic”)
	•	update_markers (e.g., “rollback”, “firmware”, “update”, “slot”, “bank”)
'''