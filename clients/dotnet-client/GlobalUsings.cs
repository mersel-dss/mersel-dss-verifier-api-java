// ─────────────────────────────────────────────────────────────────────────────
// Tüm dosyalara her iki TFM (netstandard2.0 + net8.0) için aynı şekilde inject
// edilen ortak using set'i. net8.0'ın <ImplicitUsings>'i netstandard2.0 build
// için tetiklenmediğinden, "doğal" sayılan tüm namespace'leri tek noktada
// global using olarak ilan ediyoruz; bu sayede her cs dosyasında üst kısımda
// tekrar tekrar 'using System; using System.Net.Http; ...' yazmak zorunda
// kalmıyoruz ve iki TFM arasında subtle kayma riskini ortadan kaldırıyoruz.
// ─────────────────────────────────────────────────────────────────────────────

global using System;
global using System.Collections.Generic;
global using System.IO;
global using System.Linq;
global using System.Net.Http;
global using System.Threading;
global using System.Threading.Tasks;
