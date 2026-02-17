// Minimal JS/TS example for scanner validation.
import { exec } from "node:child_process";

export async function handler(userCommand: string, url: string) {
    exec(userCommand);
    const response = await fetch(url);
    return response.text();
}
