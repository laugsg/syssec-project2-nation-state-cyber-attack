rule unknown_threat {
	meta:
		Author: "Lautaro"
		Descrption: "This rules detects wget external requests and suspicious domain"
	string:
		$wget = "wget"
		$domain = "darkl0rd"
	condition:
		$wget or $domain
} 