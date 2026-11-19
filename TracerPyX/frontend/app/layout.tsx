import type { Metadata } from "next";
import "./styles.css";

export const metadata: Metadata = { title: "TracerPyX | Reachability Analysis", description: "Python vulnerability reachability analyzer" };
export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
