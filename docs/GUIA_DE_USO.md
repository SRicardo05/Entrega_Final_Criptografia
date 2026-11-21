# Guía de uso paso a paso

Esta guía permite instalar el proyecto, ejecutarlo y comprobar cada exigencia de la entrega final en unos 10 minutos. Todos los comandos se ejecutan desde la carpeta raíz del proyecto y funcionan igual en Windows, macOS y Linux. Si en tu sistema `python` apunta a Python 2, usa `python3`.

Las salidas que se muestran son reales. Los identificadores y las claves cambian en cada ejecución.

---

## Paso 0. Requisitos

- Python 3.11 o superior: `python --version`
- Git, si se va a clonar el repositorio.

## Paso 1. Obtener el código e instalar dependencias

```
git clone https://github.com/SRicardo05/Entrega_Final_Criptografia.git
cd Entrega_Final_Criptografia
python -m venv .venv
```

Activar el entorno virtual:

| Sistema | Comando |
|---|---|
| Windows (PowerShell) | `.venv\Scripts\Activate.ps1` |
| Windows (cmd) | `.venv\Scripts\activate.bat` |
| macOS / Linux | `source .venv/bin/activate` |

Instalar las dependencias:

```
python -m pip install -r requirements-dev.txt
```

Instala `pynacl` (Ed25519), `rfc8785` (JSON canónico), `fastapi`, `uvicorn`, `httpx` y `pytest`. El entorno virtual es opcional pero recomendado.

## Paso 2. Ejecutar todas las pruebas

```
python -m pytest -q
```

Resultado esperado:

```
147 passed in 4.62s
```

### 2.1 Pruebas

Cada prueba de rechazo comprueba el **paso exacto** del pipeline de la urna (0 `FORMAT`, 1 `TOKEN`, 2 `ELEMENTS`, 3 `PROOF`, 4 `REPLAY`, 5 `COMMIT`) en el que se rechaza el ballot.

| Exigencia | Prueba | Paso de rechazo |
|---|---|---|
| Cifrado de 0 y de 1 con su prueba OR | `tests/test_or_proof.py::test_proof_vote_0_and_1_verify` | se acepta |
| Voto de valor 2 | `tests/test_ballot_box.py::test_vote_value_2` | 3 `PROOF` |
| Compromiso modificado | `tests/test_ballot_box.py::test_modified_commitment_valid_point` | 3 `PROOF` |
| Compromiso fuera del grupo | `tests/test_ballot_box.py::test_commitment_out_of_group` | 2 `ELEMENTS` |
| Reto alterado | `tests/test_ballot_box.py::test_altered_challenge` | 3 `PROOF` |
| Reto alterado conservando la suma `c0+c1` | `tests/test_ballot_box.py::test_altered_challenge_sum_preserved` | 3 `PROOF` |
| Token repetido | `tests/test_ballot_box.py::test_repeated_token` | 1 `TOKEN` |

Para ejecutar solo las de la urna:

```
python -m pytest -v tests/test_ballot_box.py -k "vote_value_2 or modified_commitment or altered_challenge or repeated_token"
```

```
tests/test_ballot_box.py::test_vote_value_2 PASSED
tests/test_ballot_box.py::test_modified_commitment_valid_point PASSED
tests/test_ballot_box.py::test_altered_challenge PASSED
tests/test_ballot_box.py::test_altered_challenge_sum_preserved PASSED
tests/test_ballot_box.py::test_repeated_token PASSED
```

### 2.2 Qué cubre cada archivo de pruebas

| Archivo | Qué comprueba |
|---|---|
| `test_group.py` | Puntos inválidos, de orden pequeño o no canónicos y escalares `>= L` se rechazan |
| `test_elgamal.py` | Cifrado, suma homomórfica y descifrado del agregado para todo `n <= 20` |
| `test_or_proof.py` | Prueba OR CDS: completitud, solidez ante manipulación y orden del transcript |
| `test_tokens.py` | Tokens HMAC: falsificación y comparación en tiempo constante |
| `test_ballot_box.py` | Pipeline de la urna con el paso de rechazo de cada ataque |
| `test_verifier.py` | Verificador offline: detecta manipulación del expediente (partes A y B) |
| `test_api.py`, `test_cli.py` | API HTTP y línea de comandos de extremo a extremo |
| `test_db.py`, `test_authority.py`, `test_models.py`, `test_bench.py` | Persistencia, autoridad, formatos y métricas |

## Paso 3. Elección completa en un solo comando

Simula una elección con N votantes (1 a 20) que votan al azar. La autoridad cierra, suma los cifrados, descifra **solo el agregado** y firma el expediente.

```
python -m evoting demo --voters 5 --seed 7 --out expediente.json
```

```
Total esperado (votos a favor): 2
Expediente escrito en expediente.json
```

`--seed` es opcional y sirve para repetir los mismos votos.

## Paso 4. Auditar el expediente con el verificador offline

El verificador lee **solo** el archivo público. No usa la base de datos ni ninguna clave privada.

```
python -m evoting verify expediente.json
```

```
A. VERIFICADO CRIPTOGRÁFICAMENTE
  [OK] Firma Ed25519 de la autoridad sobre el expediente
  [OK] Parámetros públicos válidos
  [OK] Papeletas: forma, elección y prueba OR
  [OK] Sin token_id ni cifrado repetidos
  [OK] Cantidad de papeletas dentro de n_max y de tokens emitidos
  [OK] Tokens consumidos coinciden con las papeletas
  [OK] Agregado recalculado coincide con el declarado
  Resultado de la parte A: OK

B. DECLARADO POR LA AUTORIDAD (NO VERIFICABLE: no hay prueba de descifrado correcto)
  Resultado declarado (votos a favor): 2
  Verificación de rango: dentro de rango
Clave de verificación de la autoridad: 1fb9aa2a...
```

El informe separa dos partes:

- **Parte A.** Lo que el verificador comprueba criptográficamente: la firma, cada prueba OR, que no haya duplicados y que el **agregado recalculado** por él mismo coincida con el declarado.
- **Parte B.** El resultado **anunciado por la autoridad**. Solo se puede comprobar que está en el rango `[0, número de ballots]`. Que el descifrado sea correcto **no** es verificable, porque no hay prueba de descifrado correcto (está fuera de alcance).

El comando termina con código 0 si la parte A está OK y con 1 si algo falla.

### 4.1 (Opcional) Comprobar que detecta manipulación

Abre `expediente.json`, cambia `"declared_result"` por otro número y vuelve a ejecutar `verify`. La firma deja de validar:

```
  [FALLA] Firma Ed25519 de la autoridad sobre el expediente
  ...
  Resultado de la parte A: FALLA
```

Si cambias un ballot o el agregado, también falla la parte A. Las pruebas de `test_verifier.py` automatizan estos casos.

## Paso 5. Flujo real con servidor HTTP (dos terminales)

Este paso reproduce los roles por separado: autoridad, votantes y auditor. El servidor escucha solo en `127.0.0.1` y no tiene autenticación de administrador, porque es un prototipo local.

**Terminal 1. Servidor (urna y autoridad):**

```
python -m evoting serve --db evoting.db --port 8000
```

Déjalo abierto. La documentación interactiva de la API queda en http://127.0.0.1:8000/docs.

**Terminal 2. Autoridad, votantes y auditor.** Activa también aquí el entorno virtual.

1. **La autoridad crea la elección.** Genera la clave ElGamal `x`, publica `h = g^x` e imprime los parámetros públicos.

   ```
   python -m evoting admin create --server http://127.0.0.1:8000 --question "¿Aprueba la propuesta?" --n-max 3
   ```

   ```
   ...
   election_id: a36009148ba82d0f
   ```

   Copia el `election_id`; se usa en los pasos siguientes.

2. **La autoridad emite un token de un solo uso por votante.** Cada token va autenticado con HMAC-SHA256.

   ```
   python -m evoting admin tokens --server http://127.0.0.1:8000 --election a36009148ba82d0f --count 3 --out-dir tokens
   ```

   ```
   3 tokens escritos en tokens
   ```

3. **Los votantes votan.** El cliente cifra el voto y genera la prueba OR **localmente**, y luego envía el ballot a la urna.

   ```
   python -m evoting vote --server http://127.0.0.1:8000 --token tokens/token_01.json --choice 1
   python -m evoting vote --server http://127.0.0.1:8000 --token tokens/token_02.json --choice 0
   ```

   ```
   {
     "accepted": true,
     "ballot_hash": "7626a212..."
   }
   ```

4. **Ataque: reutilizar un token.**

   ```
   python -m evoting vote --server http://127.0.0.1:8000 --token tokens/token_01.json --choice 1
   ```

   ```
   {
     "accepted": false,
     "step": "TOKEN",
     "step_number": 1,
     "reason": "token ya utilizado"
   }
   ```

5. **(Opcional) Estado público de la urna.** Muestra solo el conteo, no los votos: http://127.0.0.1:8000/urna/elections/a36009148ba82d0f/status

   ```
   {"election_id":"a36009148ba82d0f","state":"open","accepted_count":2}
   ```

6. **La autoridad cierra la elección y publica el expediente firmado.**

   ```
   python -m evoting admin close --server http://127.0.0.1:8000 --election a36009148ba82d0f --out expediente.json
   ```

   ```
   Expediente escrito en expediente.json
   Resultado declarado: 1
   ```

7. **El auditor verifica.** Es el mismo comando del Paso 4.

   ```
   python -m evoting verify expediente.json
   ```

Para detener el servidor, presiona `Ctrl + C` en la Terminal 1. Antes de repetir el flujo desde cero, borra `evoting.db` y la carpeta `tokens/`.

> `evoting.db` contiene la clave privada de la autoridad y los archivos `token_*.json` contienen secretos de votación. Por eso están en `.gitignore` y nunca se versionan.

## Paso 6. Métricas experimentales (1, 5, 10 y 20 votos)

```
python -m evoting bench --out results --repeats 5
```

Mide el tamaño del ballot (bytes), el tiempo de creación del ballot (ms), el tiempo de verificación por voto (ms) y el tiempo total de auditoría (ms). Cada valor es la mediana de las repeticiones. Imprime la tabla y sobrescribe `results/metrics.md` y `results/metrics.csv`. Los valores de referencia de la entrega están en esos archivos y en la sección de métricas de `docs/especificacion.md`. Los tiempos dependen del equipo; el tamaño del ballot (1134 bytes) no.

---


## Mapa rápido del código

```
evoting/crypto/     primitivas: grupo, ElGamal, prueba OR, JSON canónico, tokens HMAC
evoting/protocol/   autoridad (única con la clave x), urna, cliente, verificador, formatos
evoting/storage/    SQLite con restricciones UNIQUE (token y ciphertext)
evoting/api/        API FastAPI: /admin y /urna
evoting/bench.py    métricas
evoting/__main__.py línea de comandos (serve, admin, vote, verify, demo, bench)
tests/              147 pruebas con pytest
```
## Problemas comunes

| Síntoma | Solución |
|---|---|
| `No module named evoting` | Ejecuta los comandos desde la carpeta raíz del proyecto |
| `No module named nacl` (u otro paquete) | Activa el entorno virtual y repite el Paso 1 |
| PowerShell no deja activar `.venv` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, o usa `cmd` |
| `Error de conexión con el servidor` | El servidor del Paso 5 no está corriendo o el puerto es otro |
| `Error 4xx` al emitir tokens, votar o cerrar | Usa el `election_id` correcto. Si la elección ya está cerrada, crea una nueva |
| Caracteres raros (`Â¿`) en la consola de Windows | Solo afecta a la visualización. Puedes ejecutar `chcp 65001` antes |
