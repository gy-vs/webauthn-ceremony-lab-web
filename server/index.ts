import { createApp } from './app';

const port = Number(process.env.PORT || 8787);
const app = createApp();

app.listen(port, () => {
  // eslint-disable-next-line no-console
  console.log(`[webauthn-lab] API listening on http://localhost:${port}`);
  // eslint-disable-next-line no-console
  console.log(`[webauthn-lab] Vite dev server proxies /api here; production serves dist/ from the same port`);
});
