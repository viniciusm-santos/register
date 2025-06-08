import { comparePassword, generatePassword } from "./index";

describe("Hashing password function", () => {
  test("should return a non empty hashed password", async () => {
    const password = "magnolia";
    const hashedPassword = await generatePassword(password);

    expect(typeof hashedPassword).toBe("string");
    expect(hashedPassword.length).toBeGreaterThan(0);
  });

  test("should return two diffent hashed password for the same password", async () => {
    const password = "magnolia";
    const hashedPassword1 = await generatePassword(password);
    const hashedPassword2 = await generatePassword(password);

    expect(hashedPassword1).not.toEqual(hashedPassword2);
  });

  test("should return true to a valid hashed password", async () => {
    const password = "magnolia";
    const hashedPassword = await generatePassword(password);
    const isMatch = await comparePassword(password, hashedPassword);

    expect(isMatch).toBe(true);
  });

  test("should return a false to a incorrect password", async () => {
    const correctPassword = "magnolia";
    const wrongPassword = "rosas";
    const hashedPassword = await generatePassword(correctPassword);
    const isMatch = await comparePassword(wrongPassword, hashedPassword);

    expect(isMatch).toBe(false);
  });

  test("should work with empty password", async () => {
    const password = "";
    const hashedPassword = await generatePassword(password);
    const isMatch = await comparePassword(password, hashedPassword);

    expect(isMatch).toBe(true);
  });
});
