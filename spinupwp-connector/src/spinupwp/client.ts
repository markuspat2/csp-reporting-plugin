export interface ApiListResponse<T> {
  data: T[];
}

export class SpinupwpClient {
  private readonly getToken: () => string | undefined;
  private readonly baseUrl: string;

  constructor(getToken: () => string | undefined, baseUrl: string = 'https://api.spinupwp.com/v1') {
    this.getToken = getToken;
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  private authHeaders(): HeadersInit {
    const token = this.getToken();
    if (!token) {
      throw new Error('Missing SpinupWP API token');
    }
    return {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    };
  }

  async getServers(): Promise<ApiListResponse<any>> {
    const res = await fetch(`${this.baseUrl}/servers`, {
      headers: this.authHeaders(),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`SpinupWP API error ${res.status}: ${text}`);
    }
    return res.json();
  }
}

