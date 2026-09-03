import pandas as pd

vulnerabilidades = [
    {"Host": "172.19.0.4", "NVT Name": "PostgreSQL Weak Password", "Severity": 9.8, "CVEs": "CVE-2023-2453"},
    {"Host": "172.19.0.12", "NVT Name": "Remote Code Execution in JuiceShop", "Severity": 8.5, "CVEs": "CVE-2024-1024"},
    {"Host": "172.19.0.17", "NVT Name": "Nginx Insecure Cryptographic Transport", "Severity": 5.0, "CVEs": "CVE-2023-4012"},
    {"Host": "172.19.0.5", "NVT Name": "Legacy Application SQL Injection", "Severity": 7.5, "CVEs": "CVE-2022-3052"},
    {"Host": "172.19.0.8", "NVT Name": "Openvasd Configuration Defaults", "Severity": 4.3, "CVEs": "N/D"}
]

ACTIVOS = {
    "172.19.0.4":  {"nombre": "Base de datos ERP", "dueno": "Gerencia de Finanzas", "clasificacion": "Restringida", "expuesto": False, "criticidad": 5},
    "172.19.0.12": {"nombre": "Portal de clientes", "dueno": "Gerencia Comercial", "clasificacion": "Confidencial", "expuesto": True, "criticidad": 4},
    "172.19.0.17": {"nombre": "Portal corporativo", "dueno": "Gerencia Comercial", "clasificacion": "Publica", "expuesto": True, "criticidad": 2},
    "172.19.0.5":  {"nombre": "App legada interna", "dueno": "Gerencia de Operaciones", "clasificacion": "Interna", "expuesto": False, "criticidad": 3},
}

filas = []
for idx, r in enumerate(vulnerabilidades):
    a = ACTIVOS.get(r["Host"], {"nombre": "Componente Interno", "dueno": "TI", "clasificacion": "Interna", "expuesto": False, "criticidad": 2})
    prob = 5 if r["Severity"] >= 9.0 else 4 if r["Severity"] >= 7.0 else 3 if a["expuesto"] else 2
    imp = a["criticidad"]
    riesgo_inherente = prob * imp
    
    filas.append({
        "id_riesgo": f"R-{idx+1:03d}",
        "activo": a["nombre"],
        "dueno_del_riesgo": a["dueno"],
        "vulnerabilidad": r["NVT Name"],
        "cve": r["CVEs"],
        "cvss": r["Severity"],
        "probabilidad": prob,
        "impacto": imp,
        "riesgo_inherente": riesgo_inherente,
        "nivel": "Critico" if riesgo_inherente >= 20 else "Alto" if riesgo_inherente >= 12 else "Medio"
    })

reg = pd.DataFrame(filas).sort_values("riesgo_inherente", ascending=False)
reg.to_csv("40_hallazgos/PT03_registro_riesgos.csv", index=False)
print(reg.to_string(index=False))
