"""Semaforo global: suma de puntos de los indicadores segun config.json."""
from __future__ import annotations

LEVELS = {
    "verde": {"nombre": "Verde", "texto": "Sin indicios de robo de cookies", "color": "#2e9e4f"},
    "amarillo": {"nombre": "Amarillo", "texto": "Revisar: hay indicios que conviene mirar", "color": "#d9a400"},
    "rojo": {"nombre": "Rojo", "texto": "Posible robo de sesiones: rota tus sesiones YA", "color": "#c62828"},
}

NO_CERTEZA = ("CookieGuard trabaja con indicios, no con certezas: un malware sofisticado puede no dejar rastro y un "
              "phishing AiTM (tipo Evilginx) no deja huella en este equipo. Verde significa 'sin indicios', no 'seguro'.")


def evaluate(indicators: list[dict], cfg: dict) -> dict:
    total = sum(i.get("puntos", 0) for i in indicators if i.get("estado") == "alerta")
    th = cfg["umbrales"]
    if total >= th["rojo"]:
        lvl = "rojo"
    elif total >= th["amarillo"]:
        lvl = "amarillo"
    else:
        lvl = "verde"
    sin_datos = [i["nombre"] for i in indicators if i.get("estado") == "sin_datos"]
    errores = [i["nombre"] for i in indicators if i.get("estado") == "error"]
    alertas = [i for i in indicators if i.get("estado") == "alerta"]
    top = sorted(alertas, key=lambda i: -i["puntos"])[:3]
    return {"nivel": lvl, "puntos": total, **LEVELS[lvl], "indicadores_alerta": len(alertas),
            "principales": [f"{i['nombre']}: {i['resumen']}" for i in top], "sin_datos": sin_datos,
            "errores": errores, "umbrales": th, "aviso": NO_CERTEZA}
