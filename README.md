# Projet Crypto --- AES

Implémentation progressive de l'algorithme AES en Java pour le TP de
Réseaux 3.

Le projet commence par **AES-128**, puis pourra être étendu à AES-192 et
AES-256.

## État actuel

### Déjà fait

-   [x] Constructeur `AES(128)`
-   [x] `stringToBits(String message)`
-   [x] `bitsToString(int[] bits)`
-   [x] Découpage en blocs de 128 bits
-   [x] Recollage des blocs
-   [x] `xor(...)`
-   [x] `addRoundKey(...)` (opération XOR)
-   [x] Structure générale de `crypte()` / `decrypte()`

### À corriger / compléter

-   [ ] Génération réellement aléatoire de la clé maître
-   [ ] Bourrage/débourrage conforme au projet
-   [ ] S-box AES
-   [ ] S-box inverse AES
-   [ ] `createKeys()` / Key Expansion
-   [ ] `RotWord`
-   [ ] `SubWord`
-   [ ] `Rcon`
-   [ ] `subBytes()`
-   [ ] `subByteInv()`
-   [ ] `shiftRows()`
-   [ ] `shiftRowsInv()`
-   [ ] Multiplication dans `GF(2^8)`
-   [ ] `deux_a()`
-   [ ] `trois_a()`
-   [ ] `neuf_a()`
-   [ ] `onze_a()`
-   [ ] `treize_a()`
-   [ ] `quatorze_a()`
-   [ ] `prodAu()`
-   [ ] `prodAuInv()`
-   [ ] `mixColumns()`
-   [ ] `crypte(String message)`
-   [ ] `decrypte(int[] messCode)`
-   [ ] Classe `TestAES`
-   [ ] Tests de chaque méthode
-   [ ] Javadoc
-   [ ] Rendre privées les méthodes internes
-   [ ] Interface graphique finale
-   [ ] Extension AES-192
-   [ ] Extension AES-256

## Ordre conseillé

Le sujet fournit quasiment cet ordre. Il vaut mieux respecter cette
progression afin de pouvoir tester chaque morceau indépendamment.

### 1. Conversion et manipulation des données

``` text
AES
stringToBits
bitsToString
genereMasterKey
bourrage
debourrage
decoupage_en_blocs
recollage_des_bloc
xor
```

### 2. SubBytes et S-box

Commencer par stocker les tables :

``` java
private static final int[][] SBOX = ...;
private static final int[][] SBOX_INV = ...;
```

Puis implémenter :

``` text
subBytes
subByteInv
```

Test important :

``` text
subByteInv(subBytes(state)) == state
```

### 3. Key Expansion

Pour AES-128 :

``` text
clé maître = 128 bits
Nk = 4
Nr = 10
Nb = 4
```

La Key Expansion produit :

``` text
44 mots de 32 bits
↓
11 clés de ronde de 128 bits

K0 K1 K2 ... K10
```

À implémenter :

``` text
RotWord
SubWord
Rcon
createKeys
```

### 4. ShiftRows

Représentation du State :

``` text
a0  a4  a8  a12
a1  a5  a9  a13
a2  a6  a10 a14
a3  a7  a11 a15
```

Après `ShiftRows` :

``` text
a0  a4  a8  a12
a5  a9  a13 a1
a10 a14 a2  a6
a15 a3  a7  a11
```

Tester aussi immédiatement l'inverse :

``` text
shiftRowsInv(shiftRows(state)) == state
```

### 5. GF(2\^8)

AES utilise le corps fini `GF(2^8)` avec le polynôme irréductible :

``` text
x^8 + x^4 + x^3 + x + 1
```

soit :

``` text
0x11B
```

Implémenter les multiplications demandées :

``` text
deux_a
trois_a
neuf_a
onze_a
treize_a
quatorze_a
```

Puis :

``` text
prodAu
prodAuInv
```

### 6. MixColumns

Pour chaque colonne :

``` text
02 03 01 01
01 02 03 01
01 01 02 03
03 01 01 02
```

Les additions sont des XOR et les multiplications sont faites dans
`GF(2^8)`.

Tester ensuite :

``` text
prodAuInv(prodAu(state)) == state
```

### 7. Chiffrement AES-128

Structure à implémenter dans `crypte()` :

``` text
Plaintext
    ↓
AddRoundKey(K0)
    ↓
Tours 1 à 9 :
    SubBytes
    ShiftRows
    MixColumns
    AddRoundKey(Kr)
    ↓
Tour 10 :
    SubBytes
    ShiftRows
    AddRoundKey(K10)
    ↓
Ciphertext
```

**Attention : le tour 10 ne contient pas `MixColumns`.**

### 8. Déchiffrement

Utiliser les transformations inverses avec les clés dans l'ordre inverse
:

``` text
Ciphertext
    ↓
AddRoundKey(K10)
    ↓
InvShiftRows
    ↓
InvSubBytes
    ↓
InvMixColumns
    ↓
...
    ↓
AddRoundKey(K0)
    ↓
Plaintext
```

## Organisation Java conseillée

Une fois la classe fonctionnelle, la classe `AES` peut être organisée
ainsi :

``` text
AES.java

├── Constantes
│   ├── TAILLE_BLOC
│   ├── RCON
│   ├── SBOX
│   └── SBOX_INV
│
├── Attributs
│   ├── tailleCleMaitre
│   ├── nbRonde
│   ├── masterKey
│   └── keys
│
├── Conversion
│   ├── stringToBits
│   └── bitsToString
│
├── Blocs
│   ├── bourrage
│   ├── debourrage
│   ├── decoupeEnBlocs
│   └── recollageDesBlocs
│
├── Key Expansion
│   ├── RotWord
│   ├── SubWord
│   └── createKeys
│
├── Transformations
│   ├── subBytes
│   ├── subByteInv
│   ├── shiftRows
│   ├── shiftRowsInv
│   ├── mixColumns
│   └── mixColumnsInv
│
├── GF(2^8)
│   ├── deux_a
│   ├── trois_a
│   ├── neuf_a
│   ├── onze_a
│   ├── treize_a
│   ├── quatorze_a
│   ├── prodAu
│   └── prodAuInv
│
└── Chiffrement
    ├── addRoundKey
    ├── crypte
    └── decrypte
```

## Tests

Créer une classe séparée :

``` java
public class TestAES {
    public static void main(String[] args) throws Exception {
        // Tests progressifs
    }
}
```

Ne pas attendre la fin du projet pour tester.

Tester dans cet ordre :

``` text
conversion
↓
clé maître
↓
bourrage
↓
blocs
↓
XOR
↓
S-box
↓
Key Expansion
↓
ShiftRows
↓
GF(2^8)
↓
MixColumns
↓
chiffrement
↓
déchiffrement
```

Un test fondamental à obtenir à la fin est :

``` text
message
    ↓
crypte
    ↓
ciphertext
    ↓
decrypte
    ↓
message original
```

## Après AES-128

Une fois AES-128 terminé et testé :

### AES-192

``` text
clé : 192 bits
Nk : 6
Nr : 12
clés de ronde : 13
mots générés : 52
```

### AES-256

``` text
clé : 256 bits
Nk : 8
Nr : 14
clés de ronde : 15
mots générés : 60
```

AES-256 possède également une étape supplémentaire de `SubWord` pendant
la Key Expansion.

## Interface graphique

La GUI vient après l'implémentation de l'algorithme.

Elle pourra utiliser uniquement les méthodes publiques :

``` java
crypte(String message)
decrypte(int[] messCode)
```

Les autres méthodes doivent finalement être `private`.

## Référence rapide

``` text
AES-128
Bloc       = 128 bits
Clé        = 128 bits
Nb         = 4
Nk         = 4
Nr         = 10
Rounds     = 10
Round keys = 11
```

## Règle d'or pour le développement

Ne pas coder tout AES puis tester à la fin.

Chaque fonction doit être testée dès qu'elle est terminée, notamment les
fonctions inverses :

``` text
SubBytes → InvSubBytes
ShiftRows → InvShiftRows
MixColumns → InvMixColumns
```

Puis seulement après :

``` text
crypte → decrypte
```
