1. User Identification

When posting, ask only for a username (required text input, max 20 chars).

Store username in localStorage so user doesn't need to retype every time.

No passwords or auth flows. Anonymous by default if no username given.

2. Posting & Media

Posts consist of: username, text (multi-line with emojis), optional media files.

Allow uploading multiple files per post: images (jpg/png/webp), videos (mp4/webm), audio (mp3/wav), documents.

Display previews: images show thumbnails, videos show a playable preview with controls and download button, audio shows waveform player or native controls + download.

Show upload progress with cancel button.

Allow deleting posts locally if user is the author (match stored username).

Posts timestamped, shown in relative format ("2 hours ago").

3. Feed & Interactions

Infinite scroll on feed (load more posts as user scrolls).

Real-time-ish update: poll server every 15s or use SSE/WebSocket to append new posts live with fade-in animation.

Likes with animated heart button, reaction count updates immediately.

Comments with nested replies (max 3 levels).

Comments input with username autofill (from localStorage), editable before submit.

Reactions on posts & comments (at least: ❤️, 😂, 👍).

Users can delete their own comments/posts (based on username).

Clicking media opens a fullscreen/lightbox view with smooth transitions and download options.

4. Theming & UI

Dark/light toggle with animated smooth transition, remember preference in localStorage.

Use a vibrant, modern digital palette with neon blues, purples, greens.

Use smooth animations on hover, click, and transitions (fade, slide, scale).

Responsive design from mobile to desktop.

Floating "Scroll to top" button with fade in/out on scroll.

Sticky header with app name and theme toggle button.

Use accessible semantic HTML and ARIA roles.



9. Extra UX Enhancements

Typing indicator on comment box (optional).

Copy post link button.

Show "X likes" with small user avatar thumbnails in tooltip.

Hashtag highlighting in posts with clickable search (basic).

Show post owner “Premium” or “Pro” badge if username matches (optional).

10. Accessibility & SEO

Use semantic tags (<main>, <article>, <section>, <button>, <form>, etc.)

Proper alt attributes on images.

Keyboard navigable UI.

Meta tags for SEO and social sharing.

updated colours 

Modern, clean, animated front-end (vanilla JS or framework of choice).

Updated service worker and manifest.json for full PWA support.

Fully functional media uploads/downloads.

Real-time-like feed update mechanism (poll or SSE).

User experience without login, just username per post stored locally.

Responsive, accessible, and highly performant.
