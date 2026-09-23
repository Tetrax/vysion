// Bootstrap de thème — doit rester sur le chemin critique du premier rendu.
// Exécuté avant la construction du DOM : la préférence enregistrée (clair/sombre)
// est appliquée avant le premier peint, donc aucun flash perceptible. Sans
// préférence explicite, aucun attribut n'est posé et la feuille de style suit
// prefers-color-scheme via sa requête média.
// Contrainte : le CSP de production impose script-src 'self' — ce fichier doit
// donc rester un script externe de même origine (aucun script inline autorisé).
(function () {
  try {
    var stored = window.localStorage.getItem('vysion-theme')
    if (stored === 'dark' || stored === 'light') {
      document.documentElement.setAttribute('data-theme', stored)
    } else {
      document.documentElement.removeAttribute('data-theme')
    }
  } catch (error) {
    // Stockage local indisponible : le thème suit simplement le système.
  }
})()
