import { render, screen } from "@testing-library/react";
import { App } from "@/App";

describe("App", () => {
  it("renders the Keystone wordmark and a health probe", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: /keystone/i })).toBeInTheDocument();
    expect(screen.getByTestId("health")).toBeInTheDocument();
  });
});
