import time
import random
import statistics

# =====================================================
# TRABALHO: ESQUEMA CRIPTOGRÁFICO SIMPLIFICADO (Python 3.10)
# Requisitos do enunciado:
#   - GEN(seed): gera chave binária K com |K| = 4 * len(seed)
#   - ENC(K, M): cifra M com chave K -> C (mesmo tamanho)
#   - DEC(K, C): reverte a cifra e recupera M
#   - Testes: tempo, chaves equivalentes, difusão (avalanche em M), confusão (mudança na seed)
# =====================================================

# =====================================================
# CONFIGURAÇÃO DO ESQUEMA
# =====================================================
ROUNDS = 4                 # Número de rounds da cifra (trade-off: segurança x tempo)
DELTA = 0x9E3779B9         # Constante usada na expansão de seed em GEN (mistura determinística)
MIX_CONST = 0x9E3779B97F4A7C15  # Constante ímpar para mistura linear (invertível mod 2^n)

# S-Box de 4 bits (camada NÃO linear) e sua inversa (necessária para DEC) em hexadecimal
SBOX = (0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2)
INV_SBOX = [0] * 16
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i
INV_SBOX = tuple(INV_SBOX)

# =====================================================
# UTILIDADES (representação binária <-> inteiro)
# Objetivo: acelerar a execução e simplificar operações bitwise
# (ajuda no critério "tempo de execução")
# =====================================================
def _list_to_int(bits):
    """Converte lista de bits (MSB -> LSB) para inteiro."""
    x = 0
    for b in bits:
        x = (x << 1) | (b & 1)
    return x

def _int_to_bits(x, n):
    """Converte inteiro para lista de n bits (MSB -> LSB)."""
    return [(x >> (n - 1 - i)) & 1 for i in range(n)]

def _derive_subkeys(master_key, n):
    """
    Agenda de chaves (key schedule): deriva (ROUNDS + 1) subchaves de n bits.
    - Garante que ENC e DEC usem exatamente as mesmas subchaves.
    """
    mask = (1 << n) - 1
    return [
        ((master_key >> (7 * i)) | (master_key << (n - (7 * i) % n))) & mask
        for i in range(ROUNDS + 1)
    ]

def _apply_sbox(x, n, table):
    """
    Aplica uma S-Box nibble-a-nibble (4 bits por vez) ao estado inteiro x.
    - Camada não linear -> contribui para difusão/confusão (efeito avalanche).
    """
    y = 0
    for i in range(0, n, 4):
        y |= table[(x >> i) & 0xF] << i
    return y

# =====================================================
# MIX LINEAR (invertível): difusão eficiente
# - _mix: mistura (ENC)
# - _inv_mix: inversa exata (DEC)
# =====================================================
def _mix(x, n):
    """
    Camada linear invertível:
    1) rotação de bits (permuta posições)
    2) multiplicação modular por constante ímpar (invertível em 2^n)
    """
    x = ((x << 5) | (x >> (n - 5))) & ((1 << n) - 1)  # rotl(5)
    return (x * (MIX_CONST & ((1 << n) - 1))) & ((1 << n) - 1)

def _inv_mix(x, n):
    """
    Inversa exata de _mix:
    1) multiplica pelo inverso modular de MIX_CONST mod 2^n
    2) rota no sentido inverso (rotr(5))
    """
    inv = pow(MIX_CONST, -1, 1 << n)
    x = (x * inv) & ((1 << n) - 1)
    return ((x >> 5) | (x << (n - 5))) & ((1 << n) - 1)

# =====================================================
# GEN(seed)  [REQUISITO DO ENUNCIADO]
# - Entrada: seed (lista de bits)
# - Saída: K (lista de bits) com |K| = 4 * len(seed)
# =====================================================
def GEN(seed):
    """
    Geração de chave determinística a partir de seed.
    Regra do enunciado:
      |K| = 4 * len(seed)

    Estratégia:
    - Interpreta seed como inteiro k (L bits).
    - Produz 4 "blocos" sucessivos de L bits, cada um obtido por mistura/rotação.
    - Concatena os 4 blocos -> total 4*L bits.
    """
    L = len(seed)
    k = _list_to_int(seed)
    out = 0

    for i in range(4):
        # Rotação interna (mistura local no tamanho L)
        rot = ((k << 3) | (k >> max(1, L - 3))) & ((1 << L) - 1)

        # Atualiza k com constante + i, e mistura por XOR com a rotação
        k = (k + DELTA + i) ^ rot
        k &= (1 << L) - 1  # mantém exatamente L bits

        # Concatena este bloco de L bits na saída
        out = (out << L) | k

    return _int_to_bits(out, 4 * L)

# =====================================================
# ENC(K, M)  [REQUISITO DO ENUNCIADO]
# - Entrada: K e M (listas binárias) com mesmo tamanho n
# - Saída:   C (lista binária) com mesmo tamanho n
# =====================================================
def ENC(K, M):
    """
    Cifra por rounds (estrutura SPN simplificada):
      para cada round r:
        1) XOR com subchave (confusão)
        2) S-Box (não-linearidade)
        3) Mix linear (difusão)
        4) soma modular com subchave (confusão adicional)
    """
    n = len(M)
    mask = (1 << n) - 1
    state = _list_to_int(M)
    key = _list_to_int(K)
    sub = _derive_subkeys(key, n)

    for r in range(ROUNDS):
        state ^= sub[r]                    # (1) mistura com chave
        state = _apply_sbox(state, n, SBOX) # (2) não-linearidade
        state = _mix(state, n)             # (3) difusão
        state = (state + sub[r + 1]) & mask # (4) mistura com chave (mod 2^n) - confusão adicional

    return _int_to_bits(state, n)

# =====================================================
# DEC(K, C)  [REQUISITO DO ENUNCIADO]
# - Entrada: K e C (listas binárias) com mesmo tamanho n
# - Saída:   M original (lista binária)
# =====================================================
def DEC(K, C):
    """
    Descriptografia: desfaz exatamente os passos de ENC em ordem inversa.
    Isso garante o requisito de recuperação do M original.
    """
    n = len(C)
    mask = (1 << n) - 1
    state = _list_to_int(C)
    key = _list_to_int(K)
    sub = _derive_subkeys(key, n)

    for r in reversed(range(ROUNDS)):
        state = (state - sub[r + 1]) & mask          # inverso da soma modular
        state = _inv_mix(state, n)                   # inverso do mix linear
        state = _apply_sbox(state, n, INV_SBOX)      # inverso da S-Box
        state ^= sub[r]                              # inverso do XOR (o próprio XOR)

    return _int_to_bits(state, n)

# =====================================================
# TESTES  [CRITÉRIOS DO ENUNCIADO]
# 1) Tempo de execução
# 2) Chaves equivalentes (colisões para M fixo)
# 3) Difusão: alterar 1 bit de M -> quantos bits mudam em C
# 4) Confusão: alterar 1 bit da seed -> quantos bits mudam em C (M fixa)
# =====================================================
def run_tests():
    # -------------------------------------------------
    # Parâmetro para facilitar demonstração:
    # mudar SEED_LEN muda automaticamente |K| e |M| (|K| = 4*|seed|)
    # -------------------------------------------------
    SEED_LEN = 4
    seed = [random.randint(0, 1) for _ in range(SEED_LEN)]

    # Gera K conforme o requisito e cria M do mesmo tamanho (n = len(K))
    K = GEN(seed)
    msg = [random.randint(0, 1) for _ in range(len(K))]

    print("=== TAMANHOS ===")
    print("len(seed) =", len(seed))
    print("len(K)    =", len(K), "(esperado:", 4 * len(seed), ")")
    print("len(msg)  =", len(msg), "(esperado:", len(K), ")")

    # -------------------------------------------------
    # Teste básico de corretude: DEC(K, ENC(K, M)) == M
    # -------------------------------------------------
    print("\n=== REVERSIBILIDADE (DEC desfaz ENC) ===")
    C = ENC(K, msg)
    ok = (msg == DEC(K, C))
    print("OK?", ok)

    # -------------------------------------------------
    # (1) Tempo de execução: mede custo médio de ENC
    # -------------------------------------------------
    print("\n=== TEMPO (ENC) ===")
    N = 10000
    t0 = time.perf_counter()
    for _ in range(N):
        ENC(K, msg)
    t1 = time.perf_counter()
    print(f"{(t1 - t0) / N * 1e6:.2f} µs/bloco")

    # -------------------------------------------------
    # (3) Difusão / avalanche: muda 1 bit de M e mede
    # quantos bits mudam em C (ideal ~ 50% dos bits)
    # -------------------------------------------------
    print("\n=== DIFUSÃO / AVALANCHE (alterar 1 bit de M) ===")
    base = ENC(K, msg)
    diffs = []
    for i in range(len(msg)):
        m2 = msg[:]
        m2[i] ^= 1
        c2 = ENC(K, m2)
        diffs.append(sum(a != b for a, b in zip(base, c2)))

    media = statistics.mean(diffs)
    print(f"Média bits alterados: {media:.2f} de {len(msg)} ({media/len(msg)*100:.2f}%)")

    # -------------------------------------------------
    # (4) Confusão: mantém M fixa, altera 1 bit da seed,
    # e mede quantos bits mudam em C (ideal ~ 50%)
    # -------------------------------------------------
    print("\n=== CONFUSÃO (alterar 1 bit da seed, M fixa) ===")
    conf_diffs = []
    for i in range(len(seed)):
        s2 = seed[:]
        s2[i] ^= 1
        K2 = GEN(s2)
        c2 = ENC(K2, msg)
        conf_diffs.append(sum(a != b for a, b in zip(base, c2)))

    conf_media = statistics.mean(conf_diffs)
    print(f"Média bits alterados: {conf_media:.2f} de {len(msg)} ({conf_media/len(msg)*100:.2f}%)")
    print("Por posição da seed:", conf_diffs)

    # -------------------------------------------------
    # (2) Chaves equivalentes (medida prática):
    # Para M fixa, gera várias seeds -> K = GEN(seed) -> C = ENC(K, M)
    # Conta colisões: mesma cifra C produzida por chaves K diferentes
    # -------------------------------------------------
    print("\n=== CHAVES EQUIVALENTES (colisões) ===")
    TRIALS = 3000
    seen_ciphers = {}  # cifra_int -> chave_int observada
    collisions = 0

    for _ in range(TRIALS):
        s = [random.randint(0, 1) for _ in range(len(seed))]
        k_bits = GEN(s)

        c_bits = ENC(k_bits, msg)
        ci = _list_to_int(c_bits)
        ki = _list_to_int(k_bits)

        if ci in seen_ciphers and seen_ciphers[ci] != ki:
            collisions += 1
        else:
            seen_ciphers[ci] = ki

    print("Colisões (C igual com K diferente):", collisions, "em", TRIALS, "amostras")

# Execução direta do script
if __name__ == "__main__":
    run_tests()
