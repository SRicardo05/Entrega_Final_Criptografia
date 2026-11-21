# Votación electrónica binaria con ElGamal exponencial y prueba OR

Prototipo de votación de aula (hasta 20 votantes), estilo Helios. Los votos `v ∈ {0,1}` se cifran con ElGamal exponencial sobre el subgrupo primo de Ed25519, cada ballot lleva una prueba OR de Cramer–Damgård–Schoenmakers (Fiat–Shamir), la urna suma los ballots sin descifrarlos y un verificador offline audita el expediente firmado.

**¿Primera vez? Sigue la [guía de uso paso a paso](docs/GUIA_DE_USO.md):** instalación, pruebas, demo, verificación, flujo HTTP y métricas, con salidas de ejemplo.

La especificación completa (suite criptográfica, ecuaciones, transcript, pasos de rechazo, formatos y límites de la garantía) está en [`docs/especificacion.md`](docs/especificacion.md).

## Requisitos

- Python >= 3.11 (Windows, macOS o Linux).
- Dependencias: `pynacl>=1.6`, `rfc8785`, `fastapi`, `uvicorn`, `httpx`; `pytest` para desarrollo.

```
python -m pip install -r requirements-dev.txt
```

## Pruebas

```
python -m pytest -q                                              # todas
python -m pytest tests/test_ballot_box.py::test_vote_value_2 -v  # una sola
```

## Demo y verificación (en proceso, sin servidor)

```
python -m evoting demo --voters 20 --out expediente.json
python -m evoting verify expediente.json
```

`verify` imprime la parte A (verificado criptográficamente), la parte B (resultado declarado por la autoridad, no verificable) y la clave de verificación de la autoridad, que debe compararse por un canal independiente. Termina con código 0 si la parte A es correcta y 1 si no.

## Flujo con la API HTTP

La API no tiene autenticación de administrador y escucha en `127.0.0.1`: es solo para uso local.

```
# Terminal 1
python -m evoting serve --db evoting.db --port 8000

# Terminal 2
python -m evoting admin create --server http://127.0.0.1:8000 --question "¿Aprueba la propuesta?" --n-max 3
#   imprime election_id
python -m evoting admin tokens --server http://127.0.0.1:8000 --election <election_id> --count 3 --out-dir tokens
python -m evoting vote --server http://127.0.0.1:8000 --token tokens/token_01.json --choice 1
python -m evoting vote --server http://127.0.0.1:8000 --token tokens/token_02.json --choice 0
python -m evoting admin close --server http://127.0.0.1:8000 --election <election_id> --out expediente.json
python -m evoting verify expediente.json
```

Un token solo sirve una vez; un segundo voto con el mismo token se rechaza en el paso 1 (`TOKEN`).

## Métricas

```
python -m evoting bench --out results --repeats 5
```

Mide, para 1, 5, 10 y 20 votos, el tamaño del ballot, el tiempo de creación, el tiempo de verificación por voto y el tiempo total de auditoría (mediana de las repeticiones). Imprime la tabla Markdown y escribe `results/metrics.md` y `results/metrics.csv` (los resultados de referencia de la entrega están versionados en `results/` y en la sección 10 de la especificación).

## Estructura

```
evoting/
  crypto/     group.py (Ed25519 de orden primo), elgamal.py, or_proof.py (CDS + transcript),
              canonical.py (JCS y hash), tokens.py (HMAC)
  protocol/   models.py (formatos v1), authority.py (único módulo que usa la clave x),
              ballot_box.py (pipeline con RejectStep), client.py, verifier.py (offline)
  storage/    db.py (SQLite con UNIQUE en token y ciphertext)
  api/        app.py (FastAPI: routers /admin y /urna)
  bench.py    mediciones
  __main__.py CLI (serve, admin, vote, verify, demo, bench)
tests/        pruebas con pytest
docs/         especificacion.md, GUIA_DE_USO.md
```
