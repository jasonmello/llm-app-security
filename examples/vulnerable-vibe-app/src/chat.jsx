// Deliberately vulnerable demo client. DO NOT DEPLOY.
import { useState } from 'react';

export function Chat() {
  const [answer, setAnswer] = useState('');

  async function ask(question) {
    const r = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${import.meta.env.VITE_OPENAI_API_KEY}`,
      },
      body: JSON.stringify({ model: 'gpt-4o-mini', messages: [{ role: 'user', content: question }] }),
    });
    const data = await r.json();
    setAnswer(data.choices[0].message.content);
  }

  return (
    <div>
      <input onKeyDown={(e) => e.key === 'Enter' && ask(e.target.value)} />
      <div dangerouslySetInnerHTML={{ __html: answer }} />
    </div>
  );
}
