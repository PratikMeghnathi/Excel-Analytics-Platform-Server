import { resolve } from "path";
import { fileURLToPath } from "url";

const filename = fileURLToPath(import.meta.url);

export const __rootdir = resolve(filename, '../', '../', '../');
export const __uploadsDir = resolve(__rootdir, 'src', 'uploads');

export const cookieOptions = {
    httpOnly: true,
    secure: true,
    sameSite: 'None'
}
