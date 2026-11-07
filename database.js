// InherentScanner — база хэшей SHA-256.
// Чтобы добавить новый вирус, добавь запись в массив ниже.
// sha256: хэш строчными буквами (64 символа)
// name:   название детекта
// labels: список меток, которые покажутся в результате
window.DATABASE = [
  {
    sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    name: "EICAR-Test-File",
    labels: []
  },
  {
    // тот же EICAR, но с переводом строки в конце файла
    sha256: "131f95c51cc819465fa1797f6ccacf9d494aaaff46fa3eac73ae63ffbdfd8267",
    name: "EICAR-Test-File",
    labels: []
  },
  {
    sha256: "aae5a72903d98aafeee0cc1a3417ddaf21bf934d8c66174e9b7fc96c60121f03",
    name: "Multi-threat malware",
    labels: ["Trojan", "Stealer", "Clipper", "Keylogger"]
  },
  {
    // EICAR с переводом строки CRLF (Windows)
    sha256: "8b3f191819931d1f2cef7289239b5f77c00b079847b9c2636e56854d1e5eff71",
    name: "EICAR-Test-File",
    labels: []
  },
  {
    // eicar.com.txt / eicar_com.zip с eicar.org
    sha256: "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad",
    name: "EICAR-Test-File",
    labels: []
  },
  {
    // eicarcom2.zip с eicar.org
    sha256: "e1105070ba828007508566e28a2b8d4c65d192e9eaf3b7868382b7cae747b397",
    name: "EICAR-Test-File",
    labels: []
  }
];

// Сигнатура по содержимому: ловит ЛЮБОЙ настоящий EICAR-файл,
// даже если его хэш отличается (перевод строки, пробелы, другое имя).
// Строка разбита на части, чтобы антивирус не ругался на сам сайт.
window.EICAR_SIGNATURE = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
