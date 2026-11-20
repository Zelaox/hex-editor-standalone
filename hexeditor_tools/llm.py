"""Optional llama.cpp HTTP client without training or dataset collection hooks."""
from __future__ import annotations

import json
from urllib.request import Request, urlopen


class LLMClient:
    def __init__(self, base_url: str, *, timeout: int = 900, **kwargs):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout

    def generate(self, prompt: str, max_tokens: int = 2048, temperature: float = 0.7,
                 top_p: float = 0.9, top_k: int = 40, repeat_penalty: float = 1.1,
                 stop=None, stream: bool = False, grammar=None, require_timings: bool = False):
        if stream:
            raise ValueError('Use non-streaming generation for evidence-bound hypotheses')
        payload = {'prompt': prompt, 'n_predict': max_tokens, 'temperature': temperature,
                   'top_p': top_p, 'top_k': top_k, 'repeat_penalty': repeat_penalty, 'stream': False}
        if stop:
            payload['stop'] = stop
        if grammar:
            payload['grammar'] = grammar
        if require_timings:
            payload['timings_per_token'] = True
        request = Request(self.base_url + '/completion', data=json.dumps(payload).encode('utf-8'),
                          headers={'Content-Type': 'application/json'})
        with urlopen(request, timeout=self.timeout) as response:
            result = json.load(response)
        if not isinstance(result, dict):
            raise ValueError('LLM endpoint must return a JSON object')
        return result
