import React, { useState, useRef, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  Clipboard,
  Trash2,
  Lock,
  RefreshCw,
  BookOpen,
  Smartphone,
  X,
  Search,
  Volume2,
  VolumeX,
  AlertOctagon,
  Sparkles,
  PhoneCall,
  Copy,
  ChevronDown,
  ChevronUp,
  Info,
  ArrowRight,
  Check,
  Zap,
  Users,
  HelpCircle
} from 'lucide-react';

// Safe environment guard for tailwind runtime evaluation
if (typeof window !== 'undefined') {
  window.tailwind = window.tailwind || {};
}
var tailwind = typeof window !== 'undefined' ? window.tailwind : {};
if (typeof globalThis !== 'undefined') {
  globalThis.tailwind = tailwind;
}

const TRANSLATIONS = {
  taglish: {
    heroTitlePrefix: 'Start navigating',
    heroTitleHighlight: 'your mobile security.',
    heroSubtitle: 'Unlock the power of precision smishing detection with Bantay-Bait — your all-in-one Taglish NLP fraud prevention solution.',
    badgeText: '✨ Philippine Smishing Protection • Powered by RoBERTa NLP',
    detectorTab: 'SMS Smishing Detector',
    inputPlaceholder: 'Paste suspected SMS text here (e.g., GCash OTP harvesting, BDO locked account, J&T parcel fee, Shopee job offer)...',
    clearBtn: 'Clear text',
    pasteBtn: 'Paste Text',
    analyzeBtn: 'Detect SMS Scam',
    analyzingBtn: 'Analyzing SMS...',
    charLimit: 'chars',
    samplesTitle: 'Try Sample SMS (1-Tap Test):',
    verdictTitle: 'ANALYSIS RESULT',
    verdictMalicious: 'DANGEROUS (SCAM)',
    verdictSpam: 'PROMOTIONAL SPAM',
    verdictSafe: 'SAFE MESSAGE',
    confidenceLabel: 'AI Model Confidence:',
    detectedLangLabel: 'Language:',
    listenBtn: 'Listen',
    stopListenBtn: 'Stop',
    whyFlagged: 'Why was this flagged by Bantay-Bait?',
    actionHeader: 'Recommended Action:',
    reportScamBtn: 'Report to CICC Hotline 1326',
    privacyNotice: 'Privacy Guaranteed: Your phone number and text are never stored (RA 10173 Data Privacy Act).',
    seniorModeOn: 'Senior Mode: ON',
    seniorModeOff: 'Senior Mode A+',
    trustedByHeader: 'Backed by leading Philippine platforms & regulatory standards',
    whyBantayTitle: 'Why Choose Bantay-Bait\'s AI Detector',
    whyBantaySub: 'Built on academic research at Mapúa University to empower every Filipino against digital scams through localized NLP.',
    limitationNotice: 'Know the limitations of AI tools: While RoBERTa-Tagalog is optimized for Tagalog and Taglish, text containing non-standard regional dialects (Visayan, Ilocano) may return reduced confidence scores. Always verify sensitive banking transactions directly.',
    pillar1Title: 'Taglish-Aware NLP AI',
    pillar1Desc: 'Specifically trained on code-switched Tagalog and English text patterns used in Philippine smishing.',
    pillar2Title: 'Prevents Accidental Link Taps',
    pillar2Desc: 'Copy-paste workflow eliminates the risk of accidentally clicking phishing links in your SMS inbox.',
    pillar3Title: 'Privacy-First (RA 10173)',
    pillar3Desc: 'No SMS inbox permissions required. Zero personal data stored or transmitted to third parties.',
    howItWorksTitle: 'Bantay-Bait makes SMS Content Detection fast, reliable, and easy',
    step1Title: '1. Copy Suspicious Text',
    step1Desc: 'Copy the suspicious text message received in your mobile SMS inbox.',
    step2Title: '2. Paste & Analyze',
    step2Desc: 'Tap the paste button and click Detect SMS Scam to evaluate with RoBERTa-Tagalog AI.',
    step3Title: '3. Get Instant Verdict',
    step3Desc: 'Receive clear color-coded verdicts, threat explanations, and recommended safety actions.',
    faqTitle: 'Effective Usage Guidelines for SMS Safety Tools',
    guideSectionTitle: 'Common SMS Scams in the Philippines',
    guideSectionSub: 'A concise guide to identifying fraudulent SMS messages impersonating banks, e-wallets, and couriers.',
    disclaimerLowConf: 'Notice: Confidence score is reduced because text may contain a regional dialect. Review carefully.',
    modalTitle: 'Report Scam to Authorities',
    modalSub: 'Official Philippine Cybercrime Reporting Channels',
    copyReport: 'Copy Report Summary',
    copiedReport: 'Copied!',
    closeModal: 'Close',
    footerThesis: 'Bantay-Bait • Mapúa University School of IT Thesis Project (2026)',
    footerAuthors: 'Authors: Jahrivien S. Zulueta, Fatima A. Alhusain, Ma. Erykah Xyza L. Villena | Adviser: Bryan Dimabayao (Check Point)',
    maliciousAction: 'DO NOT click any link! DO NOT share your 6-digit OTP or PIN. Block this sender immediately.',
    spamAction: 'Do not reply to promotional messages from unknown senders.',
    safeAction: 'This message appears safe. Always verify sensitive transactions through official banking apps.',
    navFeatures: 'Features',
    navHowItWorks: 'How It Works',
    navScamGuide: 'Scam Taxonomy',
    navFAQ: 'FAQ',
    heroCard1Title: 'Copy & paste SMS text with zero risk',
    heroCard1Sub: 'Evaluates full text social engineering patterns without requiring you to open or tap dangerous links.',
    heroCard2Title: 'Tailor your security for GCash, Maya & BDO alerts',
    heroCard2Sub: 'Detects OTP harvesting and bank account block impersonations instantaneously.',
    sec2Heading: 'Navigate your mobile security landscape effortlessly and make informed decisions with confidence.',
    demographicTitle: 'Built for all Filipino mobile users like you',
    demographicSub: 'Designed to protect university students, working professionals, and senior citizens across Metro Manila and provinces.'
  },
  tagalog: {
    heroTitlePrefix: 'Simulang protektahan',
    heroTitleHighlight: 'ang iyong mobile security.',
    heroSubtitle: 'Gamitin ang kapangyarihan ng mabilis at tumpak na pag-detect ng smishing gamit ang Bantay-Bait — ang iyong kumpletong Taglish NLP detector.',
    badgeText: '✨ Proteksyon sa Smishing sa Pilipinas • Powered by RoBERTa NLP',
    detectorTab: 'Tagasuri ng SMS Scam',
    inputPlaceholder: 'I-paste dito ang kaduda-dudang mensahe (halimbawa: GCash OTP, BDO locked account, J&T parcel fee, Shopee job offer)...',
    clearBtn: 'Burahin ang text',
    pasteBtn: 'I-paste ang Text',
    analyzeBtn: 'Suriin ang SMS Scam',
    analyzingBtn: 'Sinusuri ang SMS...',
    charLimit: 'letra',
    samplesTitle: 'Subukan ang Halimbawang SMS (1-Pindot):',
    verdictTitle: 'RESULTA NG PAGSURI',
    verdictMalicious: 'PANGANIB (SCAM)',
    verdictSpam: 'PROMOTIONAL SPAM',
    verdictSafe: 'LIGTAS NA MENSAHE',
    confidenceLabel: 'Katiyakan ng AI Model:',
    detectedLangLabel: 'Wika:',
    listenBtn: 'Pakinggan',
    stopListenBtn: 'Ihinto',
    whyFlagged: 'Bakit ito binigyang-babala ng Bantay-Bait?',
    actionHeader: 'Dapat Mong Gawin:',
    reportScamBtn: 'I-report sa CICC Hotline 1326',
    privacyNotice: 'Ligtas sa Privacy: Hindi iniimbak ang iyong numero o mensahe (RA 10173 Data Privacy Act).',
    seniorModeOn: 'Senior Mode: Naka-ON',
    seniorModeOff: 'Senior Mode A+',
    trustedByHeader: 'Pinoprotektahan ang mga transaksyon sa mga sikat na apps sa Pilipinas',
    whyBantayTitle: 'Bakit Gamitin ang AI Detector ng Bantay-Bait',
    whyBantaySub: 'Binuo gamit ang pananaliksik sa Mapúa University upang tulungan ang bawat Pilipino laban sa digital fraud.',
    limitationNotice: 'Alamin ang limitasyon ng AI: Bagama\'t nakatutok ang RoBERTa-Tagalog sa Tagalog at Taglish, ang mga mensaheng may rehiyonal na diyalekto (Visayan, Ilocano) ay maaaring magkaroon ng mas mababang confidence score.',
    pillar1Title: 'Taglish-Aware NLP AI',
    pillar1Desc: 'Sadyang sinanay para sa wikang Tagalog at English na ginagamit sa smishing sa Pilipinas.',
    pillar2Title: 'Iwas sa Maling Pagpindot ng Link',
    pillar2Desc: 'Copy-paste workflow upang hindi mo na kailangang i-click ang delikadong link sa iyong inbox.',
    pillar3Title: 'Proteksyon sa Privacy (RA 10173)',
    pillar3Desc: 'Walang inbox permissions at walang personal na datos na ina-access o iniimbak sa server.',
    howItWorksTitle: 'Ginagawang mabilis, maaasahan, at madali ng Bantay-Bait ang pagsusuri ng SMS',
    step1Title: '1. Kopyahin ang SMS',
    step1Desc: 'Kopyahin ang natanggap na kaduda-dudang mensahe sa iyong SMS inbox.',
    step2Title: '2. I-paste at Suriin',
    step2Desc: 'Pindutin ang paste button at i-click ang Suriin para masuri ng RoBERTa AI.',
    step3Title: '3. Tingnan ang Resulta',
    step3Desc: 'Kumuha ng malinaw na babala, paliwanag, at gabay kung ano ang dapat gawin.',
    faqTitle: 'Mga Gabay sa Mabisang Paggamit ng SMS Safety Tools',
    guideSectionTitle: 'Mga Karaniwang Scam sa SMS sa Pilipinas',
    guideSectionSub: 'Mabilis na gabay upang matukoy ang mga pekeng mensahe na nagpapanggap bilang bangko o courier.',
    disclaimerLowConf: 'Paalala: Mababa ang confidence score dahil maaaring naglalaman ng rehiyonal na diyalekto. Suriing mabuti.',
    modalTitle: 'I-report ang Scam sa May-Kapangyarihan',
    modalSub: 'Opisyal na Cybercrime Reporting Channels sa Pilipinas',
    copyReport: 'Kopyahin ang Report Text',
    copiedReport: 'Na-kopya!',
    closeModal: 'Isara',
    footerThesis: 'Bantay-Bait • Mapúa University School of IT Thesis Project (2026)',
    footerAuthors: 'May-akda: Jahrivien S. Zulueta, Fatima A. Alhusain, Ma. Erykah Xyza L. Villena | Adviser: Bryan Dimabayao (Check Point)',
    maliciousAction: 'HUWAG i-click ang link! HUWAG ibigay ang iyong 6-digit OTP o PIN. I-block agad ang numerong ito.',
    spamAction: 'Huwag nang mag-reply sa mga promotional messages mula sa hindi kilalang numero.',
    safeAction: 'Ligtas ang mensaheng ito. Gayunpaman, sa opisyal na app pa rin mag-verify ng transaksyon.',
    navFeatures: 'Mga Tampok',
    navHowItWorks: 'Paano Gumagana',
    navScamGuide: 'Gabay sa Scam',
    navFAQ: 'Tulong at FAQ',
    heroCard1Title: 'Kopyahin at i-paste ang SMS nang walang panganib',
    heroCard1Sub: 'Sinusuri ang buong text nang hindi mo kailangang i-click ang delikadong link sa inbox.',
    heroCard2Title: 'I-angkop ang proteksyon para sa GCash, Maya at BDO alerts',
    heroCard2Sub: 'Mabilis na natutukoy ang pagnanakaw ng OTP at pekeng pag-lock ng bank account.',
    sec2Heading: 'Subaybayan ang iyong seguridad sa mobile nang mabilis at magpasya nang may kumpiyansa.',
    demographicTitle: 'Binuo para sa lahat ng Pilipinong gumagamit ng mobile phone',
    demographicSub: 'Pinoprotektahan ang mga estudyante, nagtatrabaho, at mga senior citizen sa buong bansa.'
  },
  english: {
    heroTitlePrefix: 'Start navigating',
    heroTitleHighlight: 'your mobile security.',
    heroSubtitle: 'Unlock the power of precision smishing detection with Bantay-Bait — your all-in-one Taglish NLP fraud prevention solution.',
    badgeText: '✨ Philippine Smishing Protection • Powered by RoBERTa NLP',
    detectorTab: 'SMS Smishing Detector',
    inputPlaceholder: 'Paste suspected SMS text here (e.g., GCash OTP harvesting, BDO locked account, J&T parcel fee, Shopee job offer)...',
    clearBtn: 'Clear text',
    pasteBtn: 'Paste Text',
    analyzeBtn: 'Detect SMS Scam',
    analyzingBtn: 'Analyzing SMS...',
    charLimit: 'chars',
    samplesTitle: 'Try Sample SMS (1-Tap Test):',
    verdictTitle: 'ANALYSIS RESULT',
    verdictMalicious: 'DANGEROUS (SCAM)',
    verdictSpam: 'PROMOTIONAL SPAM',
    verdictSafe: 'SAFE MESSAGE',
    confidenceLabel: 'AI Model Confidence:',
    detectedLangLabel: 'Language:',
    listenBtn: 'Listen',
    stopListenBtn: 'Stop',
    whyFlagged: 'Why was this flagged by Bantay-Bait?',
    actionHeader: 'Recommended Action:',
    reportScamBtn: 'Report to CICC Hotline 1326',
    privacyNotice: 'Privacy Guaranteed: Your phone number and text are never stored (RA 10173 Data Privacy Act).',
    seniorModeOn: 'Senior Mode: ON',
    seniorModeOff: 'Senior Mode A+',
    trustedByHeader: 'Backed by leading Philippine platforms & regulatory standards',
    whyBantayTitle: 'Why Choose Bantay-Bait\'s AI Detector',
    whyBantaySub: 'Built on academic research at Mapúa University to empower every Filipino against digital scams through localized NLP.',
    limitationNotice: 'Know the limitations of AI tools: While RoBERTa-Tagalog is optimized for Tagalog and Taglish, text containing non-standard regional dialects (Visayan, Ilocano) may return reduced confidence scores. Always verify sensitive banking transactions directly.',
    pillar1Title: 'Taglish-Aware NLP AI',
    pillar1Desc: 'Specifically trained on code-switched Tagalog and English text patterns used in Philippine smishing.',
    pillar2Title: 'Prevents Accidental Link Taps',
    pillar2Desc: 'Copy-paste workflow eliminates the risk of accidentally clicking phishing links in your SMS inbox.',
    pillar3Title: 'Privacy-First (RA 10173)',
    pillar3Desc: 'No SMS inbox permissions required. Zero personal data stored or transmitted to third parties.',
    howItWorksTitle: 'Bantay-Bait makes SMS Content Detection fast, reliable, and easy',
    step1Title: '1. Copy Suspicious Text',
    step1Desc: 'Copy the suspicious text message received in your mobile SMS inbox.',
    step2Title: '2. Paste & Analyze',
    step2Desc: 'Tap the paste button and click Detect SMS Scam to evaluate with RoBERTa-Tagalog AI.',
    step3Title: '3. Get Instant Verdict',
    step3Desc: 'Receive clear color-coded verdicts, threat explanations, and recommended safety actions.',
    faqTitle: 'Effective Usage Guidelines for SMS Safety Tools',
    guideSectionTitle: 'Common SMS Scams in the Philippines',
    guideSectionSub: 'A concise guide to identifying fraudulent SMS messages impersonating banks, e-wallets, and couriers.',
    disclaimerLowConf: 'Notice: Confidence score is reduced because text may contain a regional dialect. Review carefully.',
    modalTitle: 'Report Scam to Authorities',
    modalSub: 'Official Philippine Cybercrime Reporting Channels',
    copyReport: 'Copy Report Summary',
    copiedReport: 'Copied!',
    closeModal: 'Close',
    footerThesis: 'Bantay-Bait • Mapúa University School of IT Thesis Project (2026)',
    footerAuthors: 'Authors: Jahrivien S. Zulueta, Fatima A. Alhusain, Ma. Erykah Xyza L. Villena | Adviser: Bryan Dimabayao (Check Point)',
    maliciousAction: 'DO NOT click any link! DO NOT share your 6-digit OTP or PIN. Block this sender immediately.',
    spamAction: 'Do not reply to promotional messages from unknown senders.',
    safeAction: 'This message appears safe. Always verify sensitive transactions through official banking apps.',
    navFeatures: 'Features',
    navHowItWorks: 'How It Works',
    navScamGuide: 'Scam Taxonomy',
    navFAQ: 'FAQ',
    heroCard1Title: 'Copy & paste SMS text with zero risk',
    heroCard1Sub: 'Evaluates full text social engineering patterns without requiring you to open or tap dangerous links.',
    heroCard2Title: 'Tailor your security for GCash, Maya & BDO alerts',
    heroCard2Sub: 'Detects OTP harvesting and bank account block impersonations instantaneously.',
    sec2Heading: 'Navigate your mobile security landscape effortlessly and make informed decisions with confidence.',
    demographicTitle: 'Built for all Filipino mobile users like you',
    demographicSub: 'Designed to protect university students, working professionals, and senior citizens across Metro Manila and provinces.'
  }
};

const PH_SMS_SAMPLES = [
  {
    id: 'gcash-otp',
    category: 'GCash Scam',
    label: 'Malicious',
    text: 'GCash: Your account has been accessed from a new device. Verify immediately to avoid suspension: https://gcash-security-check.com/verify OTP: 884920'
  },
  {
    id: 'bdo-locked',
    category: 'Bank Alert',
    label: 'Malicious',
    text: 'BDO Alert: Ang iyong BDO Online Account ay na-block. Paki-click ang link para ma-unblock agad: http://bdo-online-auth.ph/login'
  },
  {
    id: 'jt-express',
    category: 'Package Scam',
    label: 'Malicious',
    text: 'J&T Express: Hindi maipadala ang parcel dahil kulang ang address. Paki-update ang detalye dito: http://jt-express-ph-tracking.site/claim'
  },
  {
    id: 'shopee-job',
    category: 'Job Offer Scam',
    label: 'Malicious',
    text: 'Shopee HR: Congratulation! Selected ka for Online Part-time Job. Kumita ng P1,500 - P5,000 daily. Contact Manager via WhatsApp: 09171234567'
  },
  {
    id: 'sm-promo',
    category: 'Promo Spam',
    label: 'Spam',
    text: 'SM Malls Promo: Puntos mo, I-claim mo na! Get up to 50% discount this weekend at SM Megamall. Reply STOP to unsubscribe.'
  },
  {
    id: 'legit-bank',
    category: 'Safe SMS',
    label: 'Safe',
    text: 'Your Maya One-Time PIN (OTP) is 492019. It will expire in 5 minutes. DO NOT share this code with anyone.'
  }
];

const SCAM_TAXONOMY_I18N = {
  taglish: [
    {
      id: 'gcash-maya',
      title: 'GCash / Maya OTP Harvesting',
      type: 'E-Wallet Scam',
      desc: 'Nagpapanggap bilang GCash o Maya. Sinasabing ma-deactivate ang account kung hindi ilalagay ang OTP sa link.',
      redFlags: ['May link sa dulo (.site, .top, .ph)', 'Pinagmamadali ka', 'Hinihingi ang 6-digit OTP o PIN'],
      tip: 'Tandaan: HINDI magpapadala ng link ang GCash o Maya sa SMS para mag-unblock.'
    },
    {
      id: 'bank-lock',
      title: 'Pekeng Alerto mula sa Bangko',
      type: 'Banking Fraud',
      desc: 'Sinasabing may pumalo o naka-lock ang iyong BDO, BPI, o Metrobank online account.',
      redFlags: ['Maling URL (hindi bdo.com.ph o bpi.com.ph)', 'Walang pangalan mo sa text', 'Pananakot na isasara ang account'],
      tip: 'Mag-log in LAMANG sa opisyal na mobile app ng bangko.'
    },
    {
      id: 'parcel-delivery',
      title: 'Parcel Delivery Fee Scam',
      type: 'Logistics Fraud',
      desc: 'May hindi raw maideliver na parcel mula sa J&T o LBC dahil sa kulang na address o maliit na bayad.',
      redFlags: ['Wala kang inaasahang padala', 'Hinihingan ka ng bayad sa card', 'Hindi opisyal na website'],
      tip: 'I-check ang tracking number sa opisyal na Shopping o Courier App.'
    },
    {
      id: 'fake-jobs',
      title: 'Pekeng Part-time Job Offer',
      type: 'Job Scam',
      desc: 'Nangangako ng P1,500 - P5,000 araw-araw para sa simpleng online task o social media likes.',
      redFlags: ['Galing sa random 11-digit mobile number', 'Pinapalipat ka sa WhatsApp o Telegram', 'Hihingan ka ng paunang deposit'],
      tip: 'Ang mga totoong kumpanya ay hindi hihingi ng pera para sa trabaho.'
    }
  ],
  tagalog: [
    {
      id: 'gcash-maya',
      title: 'Pagnanakaw ng GCash / Maya OTP',
      type: 'E-Wallet Scam',
      desc: 'Nagpapanggap bilang GCash o Maya. Sinasabing ma-dedeactivate ang account kapag hindi inilagay ang OTP sa link.',
      redFlags: ['May kaduda-dudang link (.site, .top)', 'Pinagmamadali ka nang labis', 'Hinihingi ang 6-digit OTP o PIN'],
      tip: 'Tandaan: HINDI kailanman magpapadala ng link ang GCash o Maya sa SMS.'
    },
    {
      id: 'bank-lock',
      title: 'Pekeng Banta mula sa Bangko',
      type: 'Banking Fraud',
      desc: 'Sinasabing naka-lock ang iyong BDO, BPI, o Metrobank account at kailangang i-verify agad.',
      redFlags: ['Maling URL (hindi bdo.com.ph o bpi.com.ph)', 'Walang personalized greeting', 'Pananakot na isasara ang account'],
      tip: 'Mag-log in lamang sa opisyal na mobile application ng bangko.'
    },
    {
      id: 'parcel-delivery',
      title: 'Padalang Parcel Delivery Scam',
      type: 'Logistics Fraud',
      desc: 'May hindi raw maideliver na padala mula sa J&T o LBC dahil sa maling address.',
      redFlags: ['Wala kang inaasahang padala', 'Hinihingan ka ng bayad gamit ang card', 'Hindi opisyal na website'],
      tip: 'Suriin ang tracking number sa opisyal na shopping app.'
    },
    {
      id: 'fake-jobs',
      title: 'Pekeng Trabaho / Job Offer',
      type: 'Job Scam',
      desc: 'Nangangako ng P1,500 - P5,000 araw-araw para sa simpleng pag-like o online tasks.',
      redFlags: ['Mula sa hindi kilalang 11-digit number', 'Pinapalipat ka sa WhatsApp o Telegram', 'Hihingan ka ng paunang deposito'],
      tip: 'Ang mga lehitimong kumpanya ay hindi hihingi ng pera upang makapagsimula.'
    }
  ],
  english: [
    {
      id: 'gcash-maya',
      title: 'GCash / Maya OTP Harvesting',
      type: 'E-Wallet Scam',
      desc: 'Impersonates GCash or Maya, warning that your account will be suspended unless verified via the link.',
      redFlags: ['Suspicious link domain (.site, .top, .ph)', 'High-pressure urgency language', 'Asks for 6-digit OTP or PIN'],
      tip: 'Remember: GCash and Maya NEVER send links via SMS to unblock or verify accounts.'
    },
    {
      id: 'bank-lock',
      title: 'Fake Banking Security Alerts',
      type: 'Banking Fraud',
      desc: 'Claims your BDO, BPI, or Metrobank account has been blocked due to unauthorized activity.',
      redFlags: ['Fake domain URL (not bdo.com.ph or bpi.com.ph)', 'No personalized greeting', 'Threats of immediate closure'],
      tip: 'Log in strictly through official mobile banking applications.'
    },
    {
      id: 'parcel-delivery',
      title: 'Parcel Delivery Fee Scam',
      type: 'Logistics Fraud',
      desc: 'Claims a J&T Express or LBC parcel cannot be delivered due to incomplete address details.',
      redFlags: ['You have no pending orders', 'Requests a small redelivery fee via card', 'Non-official domain name'],
      tip: 'Always track parcels directly inside official shopping or courier apps.'
    },
    {
      id: 'fake-jobs',
      title: 'Fake Part-time Job Offers',
      type: 'Job Scam',
      desc: 'Promises P1,500 - P5,000 daily earnings for easy online tasks or social media likes.',
      redFlags: ['Sent from random 11-digit mobile numbers', 'Redirects you to WhatsApp or Telegram', 'Requires an upfront deposit'],
      tip: 'Legitimate companies will never demand payment or deposits for employment.'
    }
  ]
};

const ANALYSIS_REASONS_I18N = {
  taglish: {
    Malicious: [
      'Naglalaman ng link o humihingi ng iyong sensitibong OTP / PIN.',
      'Gumagamit ng pananakot at pagmamadali upang kumilos ka agad.',
      'Tumatugma sa mga kilalang pattern ng GCash, BDO, o Delivery scam sa PH.'
    ],
    Spam: [
      'Naglalaman ng mga alok na discount, promo, o sale.',
      'Walang nakitang pagnanakaw ng password o OTP.'
    ],
    Safe: [
      'Walang nakitang nakakahinalang link o paghingi ng OTP.',
      'Pamantayang opisyal o personal na mensahe.'
    ]
  },
  tagalog: {
    Malicious: [
      'Naglalaman ng link o humihingi ng iyong OTP o PIN.',
      'Pinagmamadali ka upang kumilos agad nang walang pag-isip.',
      'Tumatugma sa mga kilalang pattern ng GCash, BDO, o Padala scam.'
    ],
    Spam: [
      'Naglalaman ng mga alok na bawas-presyo, promo, o sale.',
      'Walang nakitang pagnanakaw ng password o OTP.'
    ],
    Safe: [
      'Walang nakitang nakakahinalang link o paghingi ng OTP.',
      'Pamantayang opisyal o personal na mensahe.'
    ]
  },
  english: {
    Malicious: [
      'Contains a suspicious link or requests your sensitive OTP / PIN.',
      'Uses high-pressure urgency tactics urging immediate action.',
      'Matches known smishing patterns targeting GCash, BDO, or courier users.'
    ],
    Spam: [
      'Contains promotional deals, discounts, or marketing sales.',
      'No credential harvesting or password theft vectors detected.'
    ],
    Safe: [
      'No suspicious links or OTP requests detected.',
      'Standard official transaction alert or personal message.'
    ]
  }
};

export default function App() {
  const [inputText, setInputText] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [result, setResult] = useState(null);

  // Settings & Localization
  const [lang, setLang] = useState('taglish');
  const [seniorMode, setSeniorMode] = useState(false);
  const [isSpeaking, setIsSpeaking] = useState(false);

  // FAQ Accordion State
  const [openFaq, setOpenFaq] = useState(null);

  // Reporting Modal State
  const [showReportModal, setShowReportModal] = useState(false);
  const [copiedReport, setCopiedReport] = useState(false);

  const textAreaRef = useRef(null);

  const t = TRANSLATIONS[lang] || TRANSLATIONS.taglish;
  const currentScamTaxonomy = SCAM_TAXONOMY_I18N[lang] || SCAM_TAXONOMY_I18N.taglish;
  const currentReasons = ANALYSIS_REASONS_I18N[lang] || ANALYSIS_REASONS_I18N.taglish;

  useEffect(() => {
    if (typeof window !== 'undefined') {
      window.tailwind = window.tailwind || {};
    }
  }, []);

  // Base URL of the FastAPI backend. Set VITE_API_BASE_URL (Vite) or
  // NEXT_PUBLIC_API_BASE_URL (Next) as an env var on Vercel/Netlify;
  // falls back to the deployed Render URL for convenience.
  const API_BASE_URL =
    (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
    (typeof process !== 'undefined' && process.env && process.env.NEXT_PUBLIC_API_BASE_URL) ||
    'https://bantay-bait-api.onrender.com';

  const [analyzeError, setAnalyzeError] = useState(null);

  // Capitalizes the API's lowercase verdict ("malicious") to match what
  // the rest of this UI already expects ("Malicious").
  const capitalizeVerdict = (v) => (v ? v.charAt(0).toUpperCase() + v.slice(1) : 'Safe');

  const handleAnalyze = async () => {
    if (inputText.trim().length < 5) return;

    setIsAnalyzing(true);
    setResult(null);
    setAnalyzeError(null);
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();

    // Client-side mirror of backend PR-01 so we fail fast without a network call.
    if (inputText.length > 1600) {
      setAnalyzeError(
        lang === 'english'
          ? 'Message is too long (max 1,600 characters).'
          : 'Masyadong mahaba ang mensahe (max 1,600 na letra).'
      );
      setIsAnalyzing(false);
      return;
    }

    // Abort the request if it runs past the 5-second PR-04 budget so the UI
    // never hangs indefinitely on a slow/dead backend.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5500);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/detect`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: inputText, lang }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errBody = await response.json().catch(() => ({}));
        throw new Error(errBody.detail || `Request failed (${response.status})`);
      }

      const data = await response.json();
      // data: { verdict, confidence, detectedLanguage, isRegionalDialect,
      //         reducedConfidence, reasons, modelLatencyMs }

      setResult({
        verdict: capitalizeVerdict(data.verdict),
        confidence: data.confidence,
        isRegional: data.isRegionalDialect,
        reducedConfidence: data.reducedConfidence,
        detectedLang:
          data.isRegionalDialect
            ? 'Regional Dialect'
            : data.detectedLanguage === 'taglish'
            ? 'Tagalog / Taglish'
            : data.detectedLanguage === 'tagalog'
            ? 'Tagalog'
            : 'English',
        reasons: data.reasons || [],
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      });
    } catch (err) {
      clearTimeout(timeoutId);
      const message =
        err.name === 'AbortError'
          ? lang === 'english'
            ? 'The scan took too long and timed out. Please try again.'
            : 'Matagal ang pag-scan at nag-timeout. Pakisubukang muli.'
          : lang === 'english'
          ? `Could not reach the detector: ${err.message}`
          : `Hindi ma-abot ang detector: ${err.message}`;
      setAnalyzeError(message);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleSpeakVerdict = () => {
    if (!result) return;
    if ('speechSynthesis' in window) {
      if (isSpeaking) {
        window.speechSynthesis.cancel();
        setIsSpeaking(false);
        return;
      }

      let speechText = '';
      if (result.verdict === 'Malicious') {
        speechText = lang === 'english' 
          ? 'Warning! This message is identified as a Scam or Malicious. Do not click links or give your OTP.'
          : 'Babala! Ang mensaheng ito ay isang Scam o Panganib. Huwag i-click ang link at huwag ibigay ang iyong OTP.';
      } else if (result.verdict === 'Spam') {
        speechText = lang === 'english' 
          ? 'Notice. This message is identified as Promotional Spam.' 
          : 'Paalala. Ang mensaheng ito ay Promotional Spam lamang.';
      } else {
        speechText = lang === 'english' 
          ? 'Safe. This message appears to be safe.' 
          : 'Ligtas. Ang mensaheng ito ay Ligtas at walang nakitang banta.';
      }

      const utterance = new SpeechSynthesisUtterance(speechText);
      utterance.rate = seniorMode ? 0.8 : 0.95;
      utterance.lang = lang === 'english' ? 'en-US' : 'tl-PH';
      utterance.onend = () => setIsSpeaking(false);
      utterance.onerror = () => setIsSpeaking(false);

      setIsSpeaking(true);
      window.speechSynthesis.speak(utterance);
    }
  };

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setInputText(text.slice(0, 1600));
      }
    } catch (err) {
      if (textAreaRef.current) textAreaRef.current.focus();
    }
  };

  const handleClear = () => {
    setInputText('');
    setResult(null);
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  };

  const handleSampleClick = (sampleText) => {
    setInputText(sampleText);
    setResult(null);
    if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  };

  return (
    <div className={`min-h-screen bg-[#06231a] text-slate-100 font-sans selection:bg-[#d4f570] selection:text-[#06231a] ${
      seniorMode ? 'text-lg leading-relaxed' : 'text-base'
    }`}>
      
      {/* Background Speckle / Gradient Texture */}
      <div className="fixed inset-0 pointer-events-none opacity-20 z-0 bg-[radial-gradient(#d4f570_1px,transparent_1px)] [background-size:24px_24px]" />

      {/* HEADER BAR (Erudia Style) */}
      <header className="sticky top-0 z-40 backdrop-blur-xl border-b border-[#134e3e] bg-[#06231a]/90">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-4 flex items-center justify-between gap-4 relative z-10">
          
          {/* Brand Logo */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-2xl bg-[#d4f570] flex items-center justify-center text-[#06231a] font-black shadow-lg shadow-[#d4f570]/20">
              <Shield className="w-6 h-6 text-[#06231a]" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-xl tracking-tight text-white uppercase font-mono">
                  BANTAY-BAIT
                </span>
                <span className="text-[10px] font-bold uppercase tracking-wider bg-[#d4f570]/15 text-[#d4f570] border border-[#d4f570]/30 px-2 py-0.5 rounded-full">
                  RoBERTa NLP
                </span>
              </div>
            </div>
          </div>

          {/* Navigation Links (Desktop) */}
          <nav className="hidden md:flex items-center space-x-6 text-xs font-semibold text-emerald-200/80">
            <a href="#detector" className="hover:text-[#d4f570] transition">{t.navFeatures}</a>
            <a href="#scam-guide" className="hover:text-[#d4f570] transition">{t.navScamGuide}</a>
            <a href="#faq" className="hover:text-[#d4f570] transition">{t.navFAQ}</a>
          </nav>

          {/* Controls: Language Switcher + Senior Mode */}
          <div className="flex items-center space-x-2">
            
            {/* Language Switcher Toggle */}
            <div className="bg-[#0b3327] border border-[#135a47] rounded-full p-1 flex text-xs font-semibold">
              <button
                onClick={() => setLang('taglish')}
                className={`px-3 py-1 rounded-full transition ${lang === 'taglish' ? 'bg-[#d4f570] text-[#06231a] font-black' : 'text-emerald-200 hover:text-white'}`}
              >
                Taglish
              </button>
              <button
                onClick={() => setLang('tagalog')}
                className={`px-3 py-1 rounded-full transition ${lang === 'tagalog' ? 'bg-[#d4f570] text-[#06231a] font-black' : 'text-emerald-200 hover:text-white'}`}
              >
                Tagalog
              </button>
              <button
                onClick={() => setLang('english')}
                className={`px-3 py-1 rounded-full transition ${lang === 'english' ? 'bg-[#d4f570] text-[#06231a] font-black' : 'text-emerald-200 hover:text-white'}`}
              >
                English
              </button>
            </div>

            {/* Senior Mode Toggle */}
            <button
              onClick={() => setSeniorMode(!seniorMode)}
              className={`px-3.5 py-1.5 rounded-full text-xs font-bold border transition flex items-center space-x-1 ${
                seniorMode 
                  ? 'bg-amber-400 text-[#06231a] border-amber-300 font-black' 
                  : 'bg-[#0b3327] border-[#135a47] text-emerald-200 hover:bg-[#114838]'
              }`}
            >
              <span className="font-black text-sm">A+</span>
              <span className="hidden sm:inline">{seniorMode ? 'ON' : 'Senior'}</span>
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT AREA */}
      <main className="max-w-6xl mx-auto px-4 sm:px-6 py-8 space-y-12 relative z-10">
        
        {/* HERO SECTION (Erudia 3-Card Aesthetic) */}
        <section className="space-y-6">
          
          {/* Main Hero Card */}
          <div className="bg-gradient-to-br from-[#0c3f30] via-[#093529] to-[#052119] border border-[#175d4a] rounded-[36px] p-8 sm:p-12 relative overflow-hidden shadow-2xl">
            
            {/* Abstract Terrazzo Sphere graphic overlay (3D Graphic like Erudia) */}
            <div className="absolute right-[-40px] top-[-40px] w-64 h-64 sm:w-80 sm:h-80 rounded-full bg-[#d4f570]/20 blur-2xl pointer-events-none" />
            <div className="absolute right-6 top-6 w-32 h-32 sm:w-48 sm:h-48 rounded-full border-4 border-[#d4f570]/30 bg-gradient-to-tr from-[#0a382c] to-[#125845] shadow-2xl hidden md:flex items-center justify-center pointer-events-none">
              <div className="w-16 h-16 rounded-full bg-[#d4f570] text-[#06231a] flex items-center justify-center font-black">
                <Shield className="w-8 h-8" />
              </div>
            </div>

            <div className="max-w-2xl space-y-5 relative z-10">
              <div className="inline-flex items-center space-x-2 px-4 py-1.5 rounded-full bg-[#d4f570]/15 border border-[#d4f570]/30 text-[#d4f570] text-xs font-bold">
                <Sparkles className="w-3.5 h-3.5" />
                <span>{t.badgeText}</span>
              </div>

              <h1 className={`font-black text-white tracking-tight leading-tight ${seniorMode ? 'text-4xl sm:text-6xl' : 'text-3xl sm:text-5xl'}`}>
                {t.heroTitlePrefix} <span className="text-[#d4f570]">{t.heroTitleHighlight}</span>
              </h1>

              <p className="text-sm sm:text-base text-emerald-200/80 leading-relaxed max-w-xl">
                {t.heroSubtitle}
              </p>

              <div className="pt-2 flex flex-wrap items-center gap-3">
                <a
                  href="#detector"
                  className="px-6 py-3.5 rounded-full bg-[#d4f570] hover:bg-[#c3e859] text-[#06231a] font-extrabold text-xs shadow-xl flex items-center space-x-2 transition-all active:scale-95"
                >
                  <span>Start SMS Analysis</span>
                  <ArrowRight className="w-4 h-4" />
                </a>
              </div>
            </div>
          </div>

        </section>

        {/* LOGO STRIP / TRUSTED PLATFORMS */}
        <section className="text-center space-y-3 pt-2">
          <p className="text-xs font-semibold text-emerald-400/60 uppercase tracking-widest">
            {t.trustedByHeader}
          </p>
          <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-10 opacity-60 text-emerald-100 font-black text-xs sm:text-sm tracking-wider">
            <span>GCash</span>
            <span>Maya</span>
            <span>BDO Online</span>
            <span>BPI</span>
            <span>J&T Express</span>
            <span>Shopee</span>
            <span>CICC 1326</span>
          </div>
        </section>

        {/* MAIN SMS DETECTOR TOOL CONTAINER (Erudia Styled) */}
        <section id="detector" className="space-y-6 pt-4">
          <div className="bg-[#0b382c] border border-[#145d4a] rounded-[32px] p-6 sm:p-8 space-y-6 shadow-2xl relative">
            
            {/* Header pill tab */}
            <div className="flex items-center justify-between border-b border-[#135342] pb-4">
              <div className="inline-flex items-center space-x-2 px-4 py-2 rounded-full bg-[#06231a] border border-[#175d4a] text-[#d4f570] text-xs font-bold">
                <Smartphone className="w-4 h-4" />
                <span>{t.detectorTab}</span>
              </div>
              <div className="text-xs text-emerald-300/60 font-mono">
                {inputText.length} / 1600 {t.charLimit}
              </div>
            </div>

            {/* Input Text Area */}
            <div className="space-y-4">
              <textarea
                ref={textAreaRef}
                value={inputText}
                onChange={(e) => setInputText(e.target.value.slice(0, 1600))}
                placeholder={t.inputPlaceholder}
                rows={seniorMode ? 6 : 5}
                className={`w-full bg-[#06231a] border border-[#175d4a] rounded-2xl p-4 text-emerald-100 placeholder-emerald-700 focus:outline-none focus:ring-2 focus:ring-[#d4f570] focus:border-transparent resize-none leading-relaxed ${
                  seniorMode ? 'text-xl' : 'text-base'
                }`}
              />

              {/* Action Toolbar */}
              <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
                <div className="flex items-center space-x-2 w-full sm:w-auto">
                  
                  {/* Primary Trigger Button */}
                  <button
                    onClick={handleAnalyze}
                    disabled={inputText.trim().length < 5 || isAnalyzing}
                    className={`px-6 py-3.5 rounded-full font-black text-xs shadow-xl flex items-center justify-center space-x-2 transition-all ${
                      inputText.trim().length < 5 || isAnalyzing
                        ? 'bg-[#06231a] text-emerald-800 cursor-not-allowed border border-[#134e3e]'
                        : 'bg-[#d4f570] hover:bg-[#c3e859] text-[#06231a] active:scale-95 shadow-[#d4f570]/20'
                    }`}
                  >
                    {isAnalyzing ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>{t.analyzingBtn}</span>
                      </>
                    ) : (
                      <>
                        <Shield className="w-4 h-4" />
                        <span>{t.analyzeBtn}</span>
                      </>
                    )}
                  </button>

                  {/* Paste Text Button */}
                  <button
                    onClick={handlePaste}
                    className="px-4 py-3.5 rounded-full bg-[#06231a] hover:bg-[#0f4435] text-emerald-200 text-xs font-bold flex items-center justify-center space-x-1.5 border border-[#175d4a] transition"
                  >
                    <Clipboard className="w-4 h-4 text-[#d4f570]" />
                    <span>{t.pasteBtn}</span>
                  </button>

                  {/* Clear Button */}
                  {inputText && (
                    <button
                      onClick={handleClear}
                      className="px-3.5 py-3.5 rounded-full bg-[#06231a] hover:bg-[#0f4435] text-emerald-400 hover:text-emerald-200 text-xs font-semibold flex items-center justify-center space-x-1 border border-[#175d4a] transition"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>{t.clearBtn}</span>
                    </button>
                  )}
                </div>

                {/* API / Network Error Banner */}
                {analyzeError && (
                  <div className="flex items-start space-x-2 text-xs text-rose-300 bg-rose-950/40 border border-rose-800/50 rounded-xl px-3.5 py-2.5">
                    <AlertOctagon className="w-4 h-4 text-rose-400 flex-shrink-0 mt-0.5" />
                    <span>{analyzeError}</span>
                  </div>
                )}

                {/* Privacy Notice */}
                <div className="flex items-center space-x-1.5 text-xs text-emerald-400/60">
                  <Lock className="w-3.5 h-3.5 text-emerald-400" />
                  <span>{t.privacyNotice}</span>
                </div>
              </div>
            </div>

            {/* VERDICT ANALYSIS RESULT PANEL */}
            {result && !isAnalyzing && (
              <div className="space-y-4 pt-4 animate-in fade-in slide-in-from-bottom-3 duration-300">
                
                <div className={`p-6 rounded-3xl border shadow-2xl relative overflow-hidden ${
                  result.verdict === 'Malicious'
                    ? 'bg-rose-950/80 border-rose-500/60 text-rose-100'
                    : result.verdict === 'Spam'
                    ? 'bg-amber-950/80 border-amber-500/60 text-amber-100'
                    : 'bg-[#06231a] border-[#d4f570] text-emerald-100'
                }`}>
                  
                  <div className="flex items-center justify-between gap-4 flex-wrap relative z-10">
                    <div className="flex items-center space-x-4">
                      {result.verdict === 'Malicious' ? (
                        <div className="p-3 bg-rose-500/20 border border-rose-500/50 rounded-2xl text-rose-400">
                          <ShieldAlert className="w-9 h-9 animate-pulse" />
                        </div>
                      ) : result.verdict === 'Spam' ? (
                        <div className="p-3 bg-amber-500/20 border border-amber-500/50 rounded-2xl text-amber-400">
                          <AlertTriangle className="w-9 h-9" />
                        </div>
                      ) : (
                        <div className="p-3 bg-[#d4f570]/20 border border-[#d4f570]/50 rounded-2xl text-[#d4f570]">
                          <ShieldCheck className="w-9 h-9" />
                        </div>
                      )}

                      <div>
                        <span className="text-[11px] font-mono uppercase tracking-wider opacity-80 block">
                          {t.verdictTitle}
                        </span>
                        <h2 className={`font-black tracking-tight ${seniorMode ? 'text-3xl sm:text-4xl' : 'text-2xl sm:text-3xl'}`}>
                          {result.verdict === 'Malicious' 
                            ? t.verdictMalicious
                            : result.verdict === 'Spam'
                            ? t.verdictSpam
                            : t.verdictSafe}
                        </h2>
                      </div>
                    </div>

                    {/* Speech Readout Control */}
                    <button
                      onClick={handleSpeakVerdict}
                      className={`px-4 py-2.5 rounded-full border transition flex items-center space-x-2 ${
                        isSpeaking 
                          ? 'bg-[#d4f570] text-[#06231a] border-[#d4f570] font-bold animate-pulse' 
                          : 'bg-[#06231a] hover:bg-[#0f4435] border-[#175d4a] text-emerald-200'
                      }`}
                    >
                      {isSpeaking ? <VolumeX className="w-4 h-4" /> : <Volume2 className="w-4 h-4 text-[#d4f570]" />}
                      <span className="text-xs font-bold">{isSpeaking ? t.stopListenBtn : t.listenBtn}</span>
                    </button>
                  </div>

                  {/* Regional Dialect Disclaimer (Process Rule PR-02) */}
                  {result.isRegional && (
                    <div className="mt-4 p-3 rounded-2xl bg-amber-500/20 border border-amber-500/40 text-amber-200 text-xs flex items-center space-x-2">
                      <Info className="w-4 h-4 text-amber-400 shrink-0" />
                      <span>{t.disclaimerLowConf}</span>
                    </div>
                  )}

                  {/* Confidence Bar */}
                  <div className="mt-5 space-y-1.5 relative z-10">
                    <div className="flex justify-between text-xs font-mono opacity-80">
                      <span>{t.confidenceLabel}</span>
                      <span className="font-bold">{(result.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <div className="w-full h-2 bg-[#06231a] rounded-full overflow-hidden p-0.5 border border-[#175d4a]">
                      <div
                        className={`h-full rounded-full transition-all duration-700 ${
                          result.verdict === 'Malicious' ? 'bg-rose-500' : result.verdict === 'Spam' ? 'bg-amber-400' : 'bg-[#d4f570]'
                        }`}
                        style={{ width: `${result.confidence * 100}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* Threat Reasons Box */}
                <div className="bg-[#06231a] border border-[#175d4a] rounded-3xl p-6 space-y-4">
                  <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-2">
                    <Search className="w-4 h-4 text-[#d4f570]" />
                    <span>{t.whyFlagged}</span>
                  </h3>

                  <ul className="space-y-2 text-xs sm:text-sm text-emerald-200">
                    {(currentReasons[result.verdict] || []).map((reason, idx) => (
                      <li key={idx} className="flex items-start space-x-2.5 bg-[#0b382c] p-3 rounded-2xl border border-[#145d4a]">
                        <CheckCircle2 className="w-4 h-4 text-[#d4f570] shrink-0 mt-0.5" />
                        <span className="leading-relaxed">{reason}</span>
                      </li>
                    ))}
                  </ul>

                  {/* Action Guidance */}
                  <div className={`p-4 rounded-2xl border space-y-1.5 ${
                    result.verdict === 'Malicious'
                      ? 'bg-rose-950/40 border-rose-500/40 text-rose-200'
                      : result.verdict === 'Spam'
                      ? 'bg-amber-950/40 border-amber-500/40 text-amber-200'
                      : 'bg-emerald-950/40 border-emerald-500/40 text-emerald-200'
                  }`}>
                    <h4 className="font-bold text-xs uppercase tracking-wider flex items-center space-x-1.5">
                      <Shield className="w-4 h-4" />
                      <span>{t.actionHeader}</span>
                    </h4>
                    <p className={`leading-relaxed ${seniorMode ? 'text-lg' : 'text-xs sm:text-sm'}`}>
                      {result.verdict === 'Malicious'
                        ? t.maliciousAction
                        : result.verdict === 'Spam'
                        ? t.spamAction
                        : t.safeAction}
                    </p>
                  </div>

                  {/* CICC Report Button */}
                  {result.verdict === 'Malicious' && (
                    <button
                      onClick={() => setShowReportModal(true)}
                      className="w-full py-3.5 px-4 rounded-full bg-rose-600 hover:bg-rose-500 text-white font-bold text-sm flex items-center justify-center space-x-2 transition shadow-lg active:scale-95"
                    >
                      <AlertOctagon className="w-4 h-4" />
                      <span>{t.reportScamBtn}</span>
                    </button>
                  )}
                </div>
              </div>
            )}

            {/* QUICK SAMPLE TEST CARDS */}
            <div className="space-y-3 pt-2">
              <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-1.5">
                <Sparkles className="w-3.5 h-3.5 text-[#d4f570]" />
                <span>{t.samplesTitle}</span>
              </h3>

              <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                {PH_SMS_SAMPLES.map((sample) => (
                  <button
                    key={sample.id}
                    onClick={() => handleSampleClick(sample.text)}
                    className="text-left p-3.5 rounded-2xl bg-[#06231a] hover:bg-[#0f4435] border border-[#175d4a] transition group flex flex-col justify-between space-y-2"
                  >
                    <div className="flex items-center justify-between w-full">
                      <span className="text-xs font-bold text-emerald-200 group-hover:text-[#d4f570]">
                        {sample.category}
                      </span>
                      <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                        sample.label === 'Malicious'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : sample.label === 'Spam'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-[#d4f570]/20 text-[#d4f570] border border-[#d4f570]/30'
                      }`}>
                        {sample.label}
                      </span>
                    </div>
                    <p className="text-xs text-emerald-300/70 line-clamp-2 font-mono">
                      "{sample.text}"
                    </p>
                  </button>
                ))}
              </div>
            </div>

          </div>
        </section>

        {/* SECTION 4: SCAM TAXONOMY GUIDE */}
        <section id="scam-guide" className="space-y-6 pt-4">
          <div className="space-y-1">
            <h2 className="text-xl sm:text-2xl font-black text-white flex items-center space-x-2">
              <BookOpen className="w-6 h-6 text-[#d4f570]" />
              <span>{t.guideSectionTitle}</span>
            </h2>
            <p className="text-xs sm:text-sm text-emerald-300/70">{t.guideSectionSub}</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {currentScamTaxonomy.map((item) => (
              <div key={item.id} className="bg-[#0b382c] border border-[#145d4a] rounded-3xl p-6 space-y-4 hover:border-[#d4f570]/40 transition">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] font-mono font-bold text-[#d4f570] uppercase tracking-wider">{item.type}</span>
                    <h3 className="font-bold text-white text-base mt-0.5">{item.title}</h3>
                  </div>
                </div>

                <p className="text-xs text-emerald-200/80 leading-relaxed bg-[#06231a] p-3 rounded-2xl border border-[#175d4a]">
                  {item.desc}
                </p>

                <div className="space-y-1.5">
                  <span className="text-xs font-bold text-amber-400 flex items-center space-x-1">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    <span>Red Flags:</span>
                  </span>
                  <ul className="text-xs text-emerald-300/70 space-y-1 pl-4 list-disc">
                    {item.redFlags.map((rf, rIdx) => (
                      <li key={rIdx}>{rf}</li>
                    ))}
                  </ul>
                </div>

                <div className="p-3 bg-[#06231a] border border-[#d4f570]/30 rounded-2xl text-xs text-[#d4f570]">
                  <span className="font-bold block mb-0.5">Tip:</span>
                  <span>{item.tip}</span>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* SECTION 5: FAQ ACCORDION */}
        <section id="faq" className="space-y-4 pt-4">
          <div className="text-center space-y-1">
            <span className="text-xs font-bold text-[#d4f570] uppercase tracking-widest">Help & FAQ</span>
            <h2 className="text-xl sm:text-2xl font-black text-white">{t.faqTitle}</h2>
          </div>

          <div className="space-y-2.5">
            {[
              {
                q: 'How does copy-paste protect me from phishing links?',
                a: 'By copying text and analyzing it inside Bantay-Bait, you avoid tapping suspicious links in your SMS inbox (preventing accidental webpage visits).'
              },
              {
                q: 'What happens if I receive a message in Visayan or Cebuano?',
                a: 'Bantay-Bait will display a Reduced Confidence Disclaimer because RoBERTa-Tagalog is optimized for Tagalog, Taglish, and English text.'
              },
              {
                q: 'Is my phone number or SMS text stored on a server?',
                a: 'No. Bantay-Bait follows RA 10173 Data Privacy Act guidelines. Submitted texts are evaluated in real-time and never logged with phone numbers.'
              }
            ].map((item, idx) => (
              <div key={idx} className="bg-[#0b382c] border border-[#145d4a] rounded-2xl overflow-hidden">
                <button
                  onClick={() => setOpenFaq(openFaq === idx ? null : idx)}
                  className="w-full p-4 text-left font-bold text-sm text-emerald-100 flex items-center justify-between hover:text-[#d4f570] transition"
                >
                  <span>{item.q}</span>
                  {openFaq === idx ? <ChevronUp className="w-4 h-4 text-[#d4f570]" /> : <ChevronDown className="w-4 h-4 text-emerald-500" />}
                </button>
                {openFaq === idx && (
                  <div className="px-4 pb-4 text-xs text-emerald-300/80 leading-relaxed border-t border-[#135342] pt-3">
                    {item.a}
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

      </main>

      {/* EMERGENCY REPORTING MODAL */}
      {showReportModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#0b382c] border border-[#145d4a] rounded-[32px] max-w-md w-full p-6 space-y-5 relative shadow-2xl">
            <button
              onClick={() => setShowReportModal(false)}
              className="absolute top-4 right-4 text-emerald-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3">
              <div className="p-3 bg-rose-500/20 text-rose-400 rounded-2xl border border-rose-500/30">
                <AlertOctagon className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">{t.modalTitle}</h3>
                <p className="text-xs text-emerald-300/70">{t.modalSub}</p>
              </div>
            </div>

            <div className="space-y-3 text-xs sm:text-sm text-emerald-200">
              <div className="p-4 bg-[#06231a] rounded-2xl border border-[#175d4a] space-y-1">
                <span className="font-bold text-[#d4f570] block">CICC Cybercrime Hotline</span>
                <p className="text-white text-base font-black flex items-center space-x-2 mt-1">
                  <PhoneCall className="w-4 h-4 text-rose-400" />
                  <span>Dial 1326</span>
                </p>
                <p className="text-emerald-400/60 text-xs">Email: report@cicc.gov.ph</p>
              </div>

              <div className="p-3.5 bg-[#06231a] rounded-2xl border border-[#175d4a] space-y-0.5 text-xs">
                <span className="font-bold text-emerald-200">Bangko Sentral ng Pilipinas (BSP)</span>
                <p className="text-emerald-400/60">Email: consumeraffairs@bsp.gov.ph</p>
              </div>
            </div>

            <div className="pt-2 flex justify-end space-x-2">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(`[Bantay-Bait Smishing Report]\nSMS Text: ${inputText}`);
                  setCopiedReport(true);
                  setTimeout(() => setCopiedReport(false), 2000);
                }}
                className="px-4 py-2.5 bg-[#06231a] hover:bg-[#0f4435] text-emerald-200 text-xs font-bold rounded-full flex items-center space-x-1.5 border border-[#175d4a]"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>{copiedReport ? t.copiedReport : t.copyReport}</span>
              </button>

              <button
                onClick={() => setShowReportModal(false)}
                className="px-4 py-2.5 bg-[#d4f570] hover:bg-[#c3e859] text-[#06231a] font-bold text-xs rounded-full"
              >
                {t.closeModal}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FOOTER */}
      <footer className="border-t border-[#134e3e] bg-[#041a13] py-8 text-center text-xs text-emerald-400/60 space-y-2">
        <p className="font-semibold text-emerald-200/80">{t.footerThesis}</p>
        <p className="text-[11px] text-emerald-400/50 max-w-xl mx-auto px-4">{t.footerAuthors}</p>
      </footer>
    </div>
  );
}

// Simple helper icon for Senior Citizens card
function HeartIcon(props) {
  return (
    <svg {...props} fill="none" stroke="currentColor" viewBox="0 0 24 24">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4.318 6.318a4.5 4.5 0 000 6.364L12 20.364l7.682-7.684a4.5 4.5 0 00-6.364-6.364L12 7.636l-1.318-1.318a4.5 4.5 0 00-6.364 0z" />
    </svg>
  );
}