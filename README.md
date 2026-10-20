# Projet AES (TP Crypto, Réseaux 3, L3 Informatique)

Implémentation pédagogique de l'algorithme de chiffrement **AES** en Java, avec des clés de **128, 192 ou 256 bits**.

Le projet est également disponible sur GitHub : https://www.github.com/encresole/AES

## À quoi ça sert

AES (Advanced Encryption Standard) est un algorithme de chiffrement symétrique par blocs : la même clé sert à chiffrer et à déchiffrer un message. Ce projet permet de :

- chiffrer un texte (accents compris) et obtenir un tableau de bits ;
- déchiffrer ce tableau de bits pour retrouver le texte d'origine ;
- tester chaque étape de l'algorithme avec `TestAES` ;
- utiliser le tout depuis une petite interface graphique (`View`).

## Contenu du projet

| `AES.java` : La classe AES : clés, bourrage, SubBytes, ShiftRows, MixColumns, chiffrement, déchiffrement |
| `TestAES.java` : Classe de test : affiche `[OK]`, `[ECHEC]` ou `[SKIP]` pour chaque test |
| `View.java` : Interface graphique (Swing) pour chiffrer et déchiffrer un message |

## Prérequis

- **Eclipse IDE for Java Developers** (https://www.eclipse.org/downloads/)
- **JDK 11 ou plus récent** (nécessaire pour `TestAES`, qui utilise `String.repeat`)

## Récupérer le projet

Vous pouvez soit télécharger les fichiers depuis GitHub (bouton **Code > Download ZIP** sur https://www.github.com/encresole/AES), soit cloner le dépôt directement depuis Eclipse (voir la méthode 3 ci-dessous).

## Importer le projet dans Eclipse

### Méthode 1 : créer un projet et y copier les fichiers (la plus simple)

1. Dans Eclipse : **File > New > Java Project**.
2. Donnez un nom (par exemple `ProjetAES`), vérifiez que le JRE est en version 11 ou plus, puis **Finish**.
3. Dans l'explorateur de projet, faites un clic droit sur le dossier **`src`** puis **Import... > General > File System > Next**.
4. Cliquez sur **Browse** et choisissez le dossier qui contient `AES.java`, `TestAES.java` et `View.java`.
5. Cochez les trois fichiers `.java` puis **Finish**.
6. Les trois fichiers apparaissent dans `src > (default package)`.

### Méthode 2 : glisser-déposer

Copiez les trois fichiers `.java` puis collez-les sur le dossier `src` du projet dans Eclipse.

### Méthode 3 : cloner depuis GitHub dans Eclipse

1. **File > Import... > Git > Projects from Git (with smart import) > Next**.
2. Choisissez **Clone URI**, puis saisissez l'adresse `https://github.com/encresole/AES.git`.
3. Suivez l'assistant jusqu'à **Finish** : Eclipse télécharge le dépôt et crée le projet.

### Si vous avez reçu un dossier de projet Eclipse complet

**File > Import... > General > Existing Projects into Workspace**, puis sélectionnez le dossier du projet.

## Lancer le projet

Clic droit sur le fichier voulu, puis **Run As > Java Application** :

- `AES.java` : petit exemple dans `main` qui chiffre puis déchiffre `Hello, World!`.
- `TestAES.java` : lance tous les tests. Un test dont la méthode n'existe pas est marqué `[SKIP]`. Tout est bon lorsque `Tout marche !` s'affiche en bas de la console.
- `View.java` : ouvre la fenêtre graphique.

### Utiliser l'interface graphique

1. Tapez un message dans la zone du haut puis cliquez sur **Chiffrer** : le résultat s'affiche en hexadécimal.
2. Copiez ce texte hexadécimal dans la zone du haut puis cliquez sur **Déchiffrer** : le message d'origine réapparaît.

La clé est générée au lancement du programme et reste la même tant que la fenêtre est ouverte : si vous relancez `View`, la clé change et l'ancien texte chiffré ne peut plus être déchiffré.

## Utiliser la classe AES dans votre propre code

```java
AES aes = new AES(128);                  // 128, 192 ou 256
int[] chiffre = aes.crypte("Bonjour !"); // bits (0 et 1), multiple de 128
String clair = aes.decrypte(chiffre);    // "Bonjour !"
```

Seuls le constructeur, `crypte` et `decrypte` sont publics. Une mauvaise taille de clé ou un texte chiffré invalide lève une `IllegalArgumentException`.

## Remarques

- La clé maître est aléatoire et n'est pas sauvegardée : elle n'existe que pendant la vie de l'objet `AES`.
- Pour comprendre chaque fonction, voir la fiche d'explication fournie avec le projet.