# Especificación v1: votación binaria con ElGamal exponencial y prueba OR

Este documento describe lo que hace el código de `evoting/`, no solo lo que se diseñó. Cuando el diseño de la Entrega 1 y el código difieren, manda el código y la diferencia se indica en la sección 11. Responde a las tres correcciones del docente:

1. Prueba OR completa y transcript exacto: secciones 3 y 4.
2. Límite de la garantía del verificador: sección 8.
3. Suite criptográfica única y rechazo de elementos inválidos: secciones 1, 2 y 5.

## 1. Suite criptográfica v1 (corrección 3)

Se fija una sola combinación. No hay negociación de parámetros: todo objeto lleva `version = "v1"` y `group_id = "ed25519-primeorder-v1"`, y se rechaza cualquier otro valor.

| Elemento | Elección |
|---|---|
| Grupo | Subgrupo de orden primo de Ed25519, `L = 2^252 + 27742317777372353535851937790883648493`. Generador `g` = punto base estándar (hex `5866...6666`). |
| Biblioteca | PyNaCl >= 1.6, solo `nacl.bindings`. No hay aritmética de curva escrita a mano; los escalares mod `L` usan `int` de Python. |
| Escalares | 32 bytes little-endian, canónicos (`< L`), hex minúscula de 64 caracteres. |
| Puntos | 32 bytes (codificación Ed25519), hex minúscula de 64 caracteres. |
| Reto de Fiat–Shamir | `c = int_LE(SHA-512(T)) mod L` (equivale a `crypto_core_ed25519_scalar_reduce`). Usar 512 bits reduce el sesgo a un nivel despreciable. |
| Otros hashes | SHA-256 para el hash de ciphertext (anti-replay) y el `ballot_hash`; HMAC-SHA256 para los tokens. |
| Firma del expediente | Ed25519 (`nacl.signing`). La clave de verificación va dentro de los parámetros públicos. |
| Serialización | JSON canónico JCS (RFC 8785, paquete `rfc8785`). Todo lo que se hashea o se firma pasa por `canonical_bytes`. |
| Persistencia | SQLite de la biblioteca estándar (`sqlite3`). |
| HTTP | FastAPI + uvicorn. |

### 1.1 Por qué Ed25519 y no Ristretto255

La Entrega 1 proponía Ristretto255 vía PyNaCl. PyNaCl (hasta 1.6.2) no expone Ristretto255, solo aritmética Ed25519 (`crypto_core_ed25519_*`, `crypto_scalarmult_ed25519_*`). Se eligió entonces Ed25519 con PyNaCl, y se trabaja en el subgrupo de orden primo `L`.

Ed25519 tiene cofactor 8, así que la curva completa no es un grupo de orden primo y aceptar puntos sin comprobar permitiría ataques por subgrupo pequeño. Ristretto255 elimina el cofactor por construcción. Aquí se neutraliza validando cada punto recibido (sección 2).

### 1.2 Detalles de implementación de Ed25519

- `crypto_scalarmult_ed25519_noclamp` falla si el escalar es 0 o el resultado es la identidad. El envoltorio (`evoting/crypto/group.py`) trata la multiplicación por 0 y la multiplicación de la identidad como casos especiales y devuelve `IDENTITY`.
- `IDENTITY` es la constante `0x01` seguida de 31 bytes `0x00`. Se usa internamente (por ejemplo `g^0` y el agregado vacío), pero **nunca se acepta como entrada** (sección 2).
- Los escalares aleatorios son `int_LE(os.urandom(64)) mod L`, repitiendo el sorteo si sale 0.
- `Point.__add__` y `__sub__` tratan la identidad y `P - P` aparte, para mayor claridad y para no depender del comportamiento de la biblioteca con esos casos.

## 2. Validación de elementos inválidos (corrección 3)

Todo punto que llega de fuera (ballot, prueba, parámetros, expediente) se decodifica con `Point.from_hex`, que exige:

1. Cadena hex de 64 caracteres en **minúscula** (`[0-9a-f]{64}`); las mayúsculas, longitudes distintas o tipos no `str` se rechazan.
2. 32 bytes exactos.
3. `crypto_core_ed25519_is_valid_point` verdadero.

`is_valid_point` rechaza: puntos fuera de la curva, codificaciones no canónicas, puntos de orden pequeño (incluida la identidad) y puntos fuera del subgrupo de orden primo. Esta última comprobación es la que neutraliza el cofactor 8: un punto con componente de torsión no pasa. Por tanto, todos los puntos aceptados están en el subgrupo de orden `L`, y la identidad no puede aparecer como `alpha`, `beta`, compromiso ni clave.

Todo escalar se decodifica con `Scalar.from_hex`: hex minúscula de 64 caracteres, 32 bytes little-endian y valor `< L` (se rechaza `>= L`, es decir, no se reduce en silencio).

Un elemento inválido en un ballot se rechaza en el paso 2 `ELEMENTS` (sección 5), antes de evaluar ninguna ecuación de la prueba.

## 3. Cifrado y prueba OR (corrección 1)

### 3.1 ElGamal exponencial

- Clave de la autoridad: `x` aleatorio en `Z_L*`, pública `h = g^x`.
- Cifrado de `v` con aleatoriedad `r`: `(alpha, beta) = (g^r, g^v · h^r)`. Aquí `v` es 0 o 1; el cifrador acepta cualquier entero `>= 0` (así se fabrica el voto 2 en las pruebas), pero `prove` solo admite 0 y 1.
- Suma homomórfica: `(alpha1·alpha2, beta1·beta2)` cifra `g^(v1+v2)`.
- Descifrado del agregado: `target = beta · alpha^(-x) = g^S` y búsqueda lineal de `S` en `[0, n]`, donde `n` es el número de ballots aceptados. Si no aparece, se lanza `DecryptionError`.

### 3.2 Enunciado probado

Para el ciphertext `(alpha, beta)` y la clave `h`, la prueba demuestra que existe `r` y `j ∈ {0,1}` con

`alpha = g^r` y `beta · g^(-j) = h^r`,

es decir, que `(alpha, beta·g^(-j))` es una tupla Diffie–Hellman respecto a las bases `(g, h)` para `j = 0` o para `j = 1`. Eso equivale a que `beta = g^j · h^r` con `j ∈ {0,1}`. Es la prueba OR de Cramer–Damgård–Schoenmakers (CDS), hecha no interactiva con Fiat–Shamir.

Notación: `beta_0 = beta`, `beta_1 = beta · g^(-1)`. Todas las operaciones de exponentes son mod `L`.

### 3.3 Contenido de la prueba

`pi = (A0, B0, A1, B1, c0, c1, s0, s1)`:

- `A0, B0, A1, B1`: compromisos (puntos).
- `c0, c1`: retos parciales (escalares).
- `s0, s1`: respuestas (escalares).

### 3.4 Probador

Entradas: `election_id`, `token_id`, `h`, `(alpha, beta)`, voto real `v ∈ {0,1}`, aleatoriedad `r`. Sea `u = 1 - v`.

1. Rama real `v`: `w ←$ Z_L*`; `A_v = g^w`; `B_v = h^w`.
2. Rama simulada `u`: `c_u, s_u ←$ Z_L*`;
   - `A_u = g^(s_u) · alpha^(-c_u)`
   - `B_u = h^(s_u) · beta_u^(-c_u)`
3. Reto global: `c = H(T)` con `T` el transcript de la sección 4, calculado con los cuatro compromisos `A0, B0, A1, B1` ya fijados.
4. Reto de la rama real: `c_v = c - c_u mod L`.
5. Respuesta de la rama real: `s_v = w + c_v · r mod L`.
6. Salida: `pi = (A0, B0, A1, B1, c0, c1, s0, s1)`.

### 3.5 Verificador

Entradas: `election_id`, `token_id`, `h`, `(alpha, beta)`, `pi`. Acepta si y solo si se cumple **todo**:

1. (Elementos) Todos los puntos del ballot y de `pi` son válidos y todos los escalares son canónicos. Esto ocurre al decodificar, antes de las ecuaciones (sección 2).
2. (Reto) `c0 + c1 ≡ H(T) (mod L)`, con `T` reconstruido por el verificador a partir de `election_id`, `token_id`, `h`, `alpha`, `beta` y los compromisos recibidos.
3. (Ecuaciones) Para cada `j ∈ {0, 1}`:
   - `g^(s_j) = A_j · alpha^(c_j)`
   - `h^(s_j) = B_j · beta_j^(c_j)`

En el código se evalúan como `base_mul(s_j) == A_j + alpha·c_j` y `h·s_j == B_j + beta_j·c_j` (notación aditiva del wrapper). Cualquier excepción durante la verificación se interpreta como rechazo.

### 3.6 Corrección y solidez (resumen)

- **Completitud, rama real:** `g^(s_v) = g^(w + c_v r) = A_v · (g^r)^(c_v) = A_v · alpha^(c_v)`; y `h^(s_v) = h^w · (h^r)^(c_v) = B_v · beta_v^(c_v)`, porque `beta_v = h^r` cuando `v` es el voto real.
- **Completitud, rama simulada:** por construcción `g^(s_u) = A_u · alpha^(c_u)` y `h^(s_u) = B_u · beta_u^(c_u)`.
- **Suma de retos:** `c_0 + c_1 = c_u + (c - c_u) = c`.
- **Voto 2:** no existe `r` con `alpha = g^r` y `beta·g^(-j) = h^r` para ningún `j ∈ {0,1}`. Un probador que lo intente (el test `test_vote_value_2` fuerza la rama 1) obtiene una prueba que no cumple la segunda ecuación de esa rama y se rechaza en el paso 3. Para pasar tendría que predecir el reto antes de fijar los compromisos, lo que se descarta en el modelo de oráculo aleatorio.
- **Completitud:** un probador honesto (voto `v ∈ {0,1}`) siempre produce una prueba que el verificador acepta (ver las dos viñetas anteriores de rama real y simulada, y la suma de retos).
- **Solidez especial:** dadas dos transcripciones aceptadas con los mismos compromisos `(A_0, B_0, A_1, B_1)` y retos distintos `c ≠ c'`, como `c_0 + c_1 = c` y `c'_0 + c'_1 = c'`, existe `j` con `c_j ≠ c'_j`. Entonces `g^(s_j) = A_j · alpha^(c_j)` y `g^(s'_j) = A_j · alpha^(c'_j)` dan `alpha^(c_j - c'_j) = g^(s_j - s'_j)`, de donde se extrae `r = (s_j - s'_j) / (c_j - c'_j) mod L` con `alpha = g^r` y `beta_j = h^r` para la rama `j`. Por tanto, si `v ∉ {0,1}` ninguna rama tiene testigo `r`, y un tramposo debe fijar `c_j` de alguna rama antes de calcular el hash (para simularla); gana solo si el hash coincide con el reto que necesita, con probabilidad a lo sumo `q_H / L` tras `q_H` consultas al oráculo en el modelo de oráculo aleatorio.
- **HVZK (conocimiento nulo frente a verificador honesto):** la rama simulada se genera eligiendo `c_u` y `s_u` al azar y fijando `A_u = g^(s_u) · alpha^(-c_u)`, `B_u = h^(s_u) · beta_u^(-c_u)`, con la misma distribución que una rama real; la rama real tiene `c_v = c - c_u` uniforme y `s_v` uniforme, de modo que la prueba no revela cuál rama es la real (simulación perfecta de la rama falsa).

## 4. Transcript exacto de Fiat–Shamir (corrección 1)

`T` son los bytes UTF-8 de la serialización JCS (RFC 8785) del siguiente objeto, con **doce** claves:

```
{"domain":"evote/or-proof/v1","group_id":"ed25519-primeorder-v1","election_id":...,"token_id":...,
 "g":...,"h":...,"alpha":...,"beta":...,"A0":...,"B0":...,"A1":...,"B1":...}
```

Valores:

- `domain`: la cadena literal `evote/or-proof/v1` (separación de dominio).
- `group_id`: la cadena literal `ed25519-primeorder-v1`.
- `election_id`: 16 caracteres hex minúscula.
- `token_id`: 32 caracteres hex minúscula.
- `g, h, alpha, beta, A0, B0, A1, B1`: hex minúscula de 64 caracteres del punto de 32 bytes.

Todos los valores son cadenas de texto, sin espacios ni saltos de línea. JCS ordena las claves por unidades de código UTF-16, de modo que el **orden de las claves en los bytes de `T` es**:

`A0, A1, B0, B1, alpha, beta, domain, election_id, g, group_id, h, token_id`

(las mayúsculas van antes que las minúsculas, y `g` antes que `group_id` por ser prefijo). Esto se comprobó ejecutando `canonical_bytes` con las doce claves. Quien implemente el transcript por su cuenta debe usar JCS o reproducir exactamente ese orden y esa forma compacta.

Reto: `c = int_LE(SHA-512(T)) mod L`.

Por qué cada campo:

- `domain`, `group_id`: evitan reutilizar la prueba en otro protocolo o suite.
- `election_id`: evita reutilizar el ballot en otra elección.
- `token_id`: amarra la prueba al token. Copiar un ballot ajeno con otro token invalida la prueba (el reto cambia). Esto mitiga la copia de ballots al estilo Helios, aunque no la elimina: ver `REPLAY` en la sección 5.
- `g`, `h`: amarran la prueba a la clave de la elección.
- `alpha`, `beta`: el enunciado.
- `A0, B0, A1, B1`: los compromisos, como exige Fiat–Shamir "fuerte" (se hashea el enunciado y los compromisos).

## 5. Pipeline de la urna y `RejectStep`

`BallotBox.submit(raw)` nunca lanza excepciones: ante un error inesperado devuelve rechazo en `FORMAT` (falla cerrada). Cada rechazo devuelve el paso (`RejectStep`) y un motivo en español. Los pasos se evalúan en este orden:

| Valor | `RejectStep` | Qué comprueba | Rechaza |
|---|---|---|---|
| 0 | `FORMAT` | Forma estricta: claves exactas, tipos `str`, `version = "v1"`, `group_id` correcto, hex minúscula con la longitud exacta, `timestamp` no vacío, formato del token; la elección existe y está abierta | JSON mal formado, componentes faltantes o de tipo erróneo, hex en mayúscula, elección inexistente o cerrada, token con formato inválido |
| 1 | `TOKEN` | El `election_id` del token coincide; el HMAC es válido; el token no está consumido | Token de otra elección, forjado o inexistente; **token repetido**; reenvío exacto |
| 2 | `ELEMENTS` | Cada punto pasa `is_valid_point` y cada escalar es canónico (`< L`) | Punto fuera de la curva, de orden pequeño, con torsión, no canónico; escalar `>= L` |
| 3 | `PROOF` | Ecuaciones CDS y reto de Fiat–Shamir (sección 3.5) | **Voto = 2**, **compromiso modificado**, **reto alterado**, respuesta alterada, ballot copiado con otro token |
| 4 | `REPLAY` | `SHA-256(JCS({"alpha":...,"beta":...}))` no está ya registrado | Ciphertext copiado con prueba regenerada |
| 5 | `COMMIT` | Transacción SQLite atómica que guarda el ballot y consume el token; `UNIQUE` en `token_id` y en el hash de ciphertext | Carrera por doble consumo |

Observaciones sobre el orden y el estado:

- El paso 1 va antes que el 2: un token falso se rechaza sin procesar elementos de grupo.
- El reenvío exacto de un ballot ya aceptado cae en el paso 1, no en el 4, porque su token ya está consumido. `REPLAY` solo se alcanza con un token distinto (o no consumido) y el mismo ciphertext.
- Al aceptar, la urna guarda y publica el ballot **sin** el secreto ni el tag del token (`PublishedBallot`, con solo `token_id`). La respuesta incluye `ballot_hash = SHA-256(JCS(ballot publicado))`.

### 5.1 Atomicidad entre cierre y envío

Entre comprobar que la elección está abierta (paso 0) y guardar el ballot (paso 5) otro hilo podría cerrar la elección. Por eso `Store.commit_ballot` vuelve a leer el estado **dentro de la misma transacción** que inserta el ballot y consume el token. Si la elección ya no está abierta se aborta con `ElectionClosedError` y la urna lo reporta como rechazo `FORMAT` ("la elección está cerrada"). Resultado: un ballot que no está en la base antes del cierre no puede entrar después, y el agregado del expediente corresponde exactamente a los ballots guardados. Lo cubre `test_close_race_maps_to_format`.

El doble consumo (dos envíos concurrentes con el mismo token o el mismo ciphertext) se resuelve igualmente en la transacción: las restricciones `UNIQUE` hacen fallar el segundo `INSERT` (`DuplicateError`, rechazo `COMMIT`), y el consumo del token solo prospera si estaba sin consumir.

### 5.2 Tabla de casos de rechazo (pruebas de `tests/test_ballot_box.py`)

| Caso | Test | Paso |
|---|---|---|
| Voto = 2 (`g^2 · h^r` con prueba de la rama 1 "lo mejor posible") | `test_vote_value_2` | 3 `PROOF` |
| Compromiso `A0` reemplazado por otro punto válido | `test_modified_commitment_valid_point` | 3 `PROOF` |
| Compromiso `A0` fuera del grupo (orden 2, o `y = p` no canónico) | `test_commitment_out_of_group` | 2 `ELEMENTS` |
| Reto alterado (`c0 + 1`) | `test_altered_challenge` | 3 `PROOF` |
| Respuesta alterada (`s1 + 1`) | `test_altered_response` | 3 `PROOF` |
| `alpha` de orden pequeño | `test_alpha_small_order` | 2 `ELEMENTS` |
| Componente faltante (`beta`) | `test_missing_component` | 0 `FORMAT` |
| Tipo erróneo (número, `null`, lista, o ballot que no es objeto) | `test_wrong_types_rejected_at_format` | 0 `FORMAT` |
| Hex en mayúscula | `test_uppercase_hex_rejected_at_format` | 0 `FORMAT` |
| Elección inexistente o cerrada | `test_unknown_or_closed_election` | 0 `FORMAT` |
| Token con `tag` falso | `test_forged_token` | 1 `TOKEN` |
| Token de otra elección | `test_token_other_election` | 1 `TOKEN` |
| **Token repetido** | `test_repeated_token` | 1 `TOKEN` |
| Reenvío exacto | `test_exact_replay` | 1 `TOKEN` |
| Ballot aceptado copiado con un token nuevo | `test_copied_ballot_new_token` | 3 `PROOF` (la prueba está amarrada al `token_id`) |
| Ciphertext copiado con prueba regenerada y token nuevo | `test_copied_ciphertext_regenerated_proof` | 4 `REPLAY` |
| Carrera de doble consumo (las comprobaciones previas se simulan ciegas) | `test_commit_race` | 5 `COMMIT` |
| Elección cerrada entre la comprobación y el guardado | `test_close_race_maps_to_format` | 0 `FORMAT` |

Los cuatro casos que pidió el docente son: voto 2, compromiso modificado, reto alterado y token repetido, con rechazo en los pasos 3, 3, 3 y 1 respectivamente.

## 6. Tokens

Cada token es `{"version","election_id","token_id","secret","tag"}`:

- `token_id`: 16 bytes aleatorios (`secrets.token_hex(16)`, 32 hex).
- `secret`: 32 bytes aleatorios (64 hex).
- `tag = HMAC-SHA256(token_key, JCS({"election_id","token_id","secret"}))`, hex de 64 caracteres. La `token_key` (32 bytes) es una clave por elección que solo conoce la autoridad.
- La comparación del tag usa `hmac.compare_digest`.
- La autoridad no puede emitir más tokens que `n_max`, y solo mientras la elección esté abierta.
- Unicidad de consumo: además de la comprobación de la urna, la base de datos garantiza que un `token_id` solo se consume una vez.

## 7. Formatos JSON v1

Todos los valores de punto/escalar son hex minúscula de 64 caracteres, salvo donde se indique. Las claves son exactamente las listadas: faltantes o sobrantes se rechazan.

**Parámetros públicos (`params`)**

```json
{"version": "v1", "election_id": "<16 hex>", "group_id": "ed25519-primeorder-v1",
 "generator": "<g, hex>", "public_key": "<h, hex>", "n_max_voters": 20,
 "allowed_options": [0, 1], "question": "<texto>", "authority_verify_key": "<64 hex>"}
```

`n_max_voters` está entre 1 y 20. `generator` debe ser el punto base.

**Token**: ver sección 6.

**Ballot enviado a la urna**

```json
{"version": "v1", "election_id": "<16 hex>", "group_id": "ed25519-primeorder-v1",
 "token": {"version": "v1", "election_id": "...", "token_id": "<32 hex>",
           "secret": "<64 hex>", "tag": "<64 hex>"},
 "ciphertext": {"alpha": "<hex>", "beta": "<hex>"},
 "proof": {"A0": "", "B0": "", "A1": "", "B1": "", "c0": "", "c1": "", "s0": "", "s1": ""},
 "timestamp": "<ISO 8601 UTC>"}
```

Con las ocho claves de `proof` en hex de 64 caracteres. En el estado actual el ballot mide 1134 bytes en JCS (sección 10). `timestamp` es informativo: no entra en el transcript ni está autenticado.

**Ballot publicado (`PublishedBallot`)**: igual que el anterior, pero con `"token_id": "<32 hex>"` en lugar del objeto `token`. Es lo que se guarda y aparece en el expediente.

**Expediente**

```json
{"version": "v1",
 "params": { ...parámetros públicos... },
 "tokens_issued": 5,
 "consumed_token_ids": ["<32 hex>", ...],
 "ballots": [ ...ballots publicados, en orden de aceptación... ],
 "aggregate": {"alpha": "<hex>", "beta": "<hex>"},
 "declared_result": 3,
 "closed_at": "<ISO 8601 UTC>",
 "signature": "<128 hex>"}
```

`signature` es la firma Ed25519 (64 bytes, 128 hex) sobre los bytes JCS del expediente **sin** el campo `signature`, con la clave `params.authority_verify_key`.

## 8. Verificador y límite de la garantía (corrección 2)

El verificador (`evoting/protocol/verifier.py`, comando `python -m evoting verify`) funciona sin conexión y lee solo el archivo del expediente. Reporta dos partes **por separado**.

### A. Verificado criptográficamente

- La firma Ed25519 sobre el expediente es válida respecto a la clave del propio expediente.
- Los parámetros públicos son válidos.
- Cada ballot: forma correcta, pertenece a la elección y su prueba OR se verifica (sección 3.5) con `h` de los parámetros. Incluye la validación de elementos de la sección 2.
- No hay `token_id` repetidos, ni ciphertexts repetidos, ni ids repetidos en `consumed_token_ids`.
- `n_ballots <= n_max` y `n_ballots <= tokens_issued`.
- `consumed_token_ids` coincide, como conjunto, con los `token_id` de los ballots.
- El **agregado recalculado** a partir de los ballots (producto componente a componente) es igual al agregado declarado.

El reporte A es `OK` solo si todas esas comprobaciones pasan.

### B. Declarado por la autoridad (NO verificable)

- `declared_result` (número de votos a favor, `S`): el verificador **no puede comprobarlo**. Solo verifica que `0 <= S <= n_ballots` ("dentro de rango" o "fuera de rango").
- No existe una prueba de descifrado correcto (por ejemplo una prueba de igualdad de logaritmos discretos entre `h = g^x` y `beta/g^S = alpha^x`). Está fuera de alcance. Por eso el verificador **no** afirma que el resultado anunciado sea el correcto: solo que el agregado cifrado de los ballots válidos es el que muestra el expediente. Quien conozca `x` (la autoridad) puede descifrar y comparar, pero un tercero no.

### 8.1 Qué no cubre la parte A

- **Origen de la clave de verificación.** El expediente trae su propia clave de firma. Un atacante que fabrique un expediente completo con otra clave pasaría la parte A. Hay que comparar la clave (`python -m evoting verify` la imprime al final) por un canal independiente.
- **Autenticidad de los tokens.** Los tokens se autentican con HMAC de clave secreta, así que el verificador público no puede comprobarlos: solo comprueba unicidad y el límite `tokens_issued`. Una autoridad deshonesta que añada ballots propios, firmando el expediente, no es detectable si respeta `n_ballots <= tokens_issued`.
- **Ballots omitidos.** El verificador no sabe qué ballots recibió la urna; no puede detectar uno que se omitió (la urna es semihonesta).
- **Privacidad.** Los ballots son cifrados con la clave de la autoridad, que podría descifrar ballots individuales; el modelo asume una autoridad que no lo hace, y el sistema solo la obliga a publicar el agregado.

## 9. Interfaz y CLI

- Un solo proceso FastAPI con dos routers: `/admin` (crear elección, emitir tokens, cerrar, descargar expediente) y `/urna` (parámetros, estado agregado sin ballots individuales, enviar ballot).
- La API **no tiene autenticación de administrador**: es un prototipo local. `python -m evoting serve` escucha por defecto en `127.0.0.1`. No debe exponerse a una red no confiable. Cualquiera que llegue a `/admin` puede crear elecciones, emitir tokens y cerrar.
- Los errores de la urna se devuelven con HTTP 400 y `{"accepted": false, "step": "<RejectStep>", "step_number": N, "reason": "..."}`.
- `GET /urna/elections/{id}/status` devuelve solo el estado y la cantidad de ballots aceptados.
- Comandos: `serve`, `admin create|tokens|close`, `vote`, `verify`, `demo`, `bench` (ver `README.md`).
- La clave `x`, la clave HMAC y la semilla de firma están en la base de datos del servidor (tabla `authority_secrets`), en claro; solo `authority.py` y el almacenamiento las tocan. Es aceptable para el prototipo, no para producción.

## 10. Resultados experimentales

Comando: `python -m evoting bench --out results --repeats 5`. Cada fila es la mediana de 5 repeticiones, cada una con una elección nueva (`n_max = N`, `N` tokens, `N` ballots, cierre).

- `Tamaño de ballot`: `len(JCS(ballot.to_dict()))`, incluye token y timestamp.
- `Tiempo de creación`: tiempo de `build_ballot` **por ballot** (el tiempo total de los `N` ballots dividido por `N`).
- `Tiempo de verificación por voto`: tiempo de `BallotBox.submit` por ballot (pipeline completo: forma, HMAC, elementos, prueba OR, anti-replay y commit SQLite en memoria).
- `Tiempo total de auditoría`: tiempo de `verify_expediente` sobre el expediente cerrado.

Máquina: `Windows-10-10.0.26300-SP0` (Windows 11), Python 3.11.4, `AMD64` (Intel64 Family 6 Model 165, GenuineIntel), PyNaCl vía `nacl.bindings`, SQLite en memoria. Los tiempos dependen de la máquina y varían entre ejecuciones.

| N.º de votos | Tamaño de ballot (bytes) | Tiempo de creación (ms) | Tiempo de verificación por voto (ms) | Tiempo total de auditoría (ms) |
|---|---|---|---|---|
| 1 | 1134 | 1.357 | 2.430 | 2.389 |
| 5 | 1134 | 1.344 | 2.911 | 12.162 |
| 10 | 1134 | 1.445 | 2.921 | 22.718 |
| 20 | 1134 | 1.337 | 2.446 | 45.530 |

Lectura: el tamaño y los tiempos por voto no dependen de `N`; la auditoría crece de forma lineal (unos 2.2 ms por ballot, dominados por las ocho multiplicaciones escalares de la verificación de la prueba).

## 11. Decisiones propias y diferencias con la Entrega 1

| Tema | Entrega 1 / diseño | Implementación | Motivo |
|---|---|---|---|
| Grupo | Ristretto255 | Subgrupo primo de Ed25519, con `is_valid_point` | PyNaCl no expone Ristretto255 (sección 1.1) |
| Persistencia | SQLite con SQLModel (opción) | `sqlite3` de la biblioteca estándar | Menos dependencias; las restricciones `UNIQUE` y las transacciones se escriben a mano |
| Servicios | Cuatro componentes sobre una API HTTP | Un solo proceso con routers `/admin` y `/urna`; verificador y cliente como módulos y CLI | Más simple y reproducible. El cliente no usa claves de la autoridad; el verificador solo lee el archivo |
| Transcript | No estaba especificado | Incluye `token_id` | Amarra la prueba al token y mitiga la copia de ballots |
| Reto | SHA-256 (opción) | SHA-512 reducido mod `L` | Reducir 512 bits da un reto sin sesgo apreciable; SHA-256 queda para otros hashes |
| Orden de la urna | token, prueba, replay, commit (4 pasos) | 6 pasos con `RejectStep`: `FORMAT`, `TOKEN`, `ELEMENTS`, `PROOF`, `REPLAY`, `COMMIT` | Se pidió indicar el paso exacto de cada rechazo y validar elementos antes de procesar |
| Cierre vs envío | No especificado | El estado se comprueba dentro de la transacción de commit (sección 5.1) | Evita que un ballot entre después del cierre |
| Cierre repetido | No especificado | `close` es idempotente: devuelve el expediente ya firmado | Evita firmar dos expedientes distintos |
| Descifrado | Búsqueda en `[0, n]` | Búsqueda en `[0, n_ballots]` | Es el máximo posible dado lo aceptado |
| Auth de `/admin` | No especificado | Ninguna; escucha en `127.0.0.1` | Prototipo local (sección 9) |

## 12. Fuera de alcance

Anonimato de red, resistencia a coerción, descifrado por umbral o varias autoridades, blockchain, varias preguntas, voto ponderado y prueba criptográfica del descifrado final.
