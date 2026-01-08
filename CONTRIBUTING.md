# Contributing to keycloak-gsis-provider

Thank you for your interest in contributing to keycloak-gsis-provider! We welcome contributions from the community and appreciate your efforts to help improve this project.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the issue list as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps which reproduce the problem** in as many details as possible
- **Provide specific examples to demonstrate the steps**
- **Describe the behavior you observed after following the steps** and point out what exactly is the problem with that behavior
- **Explain which behavior you expected to see instead and why**
- **Include screenshots and animated GIFs if possible**
- **Include your environment details** (OS, Java version, Keycloak version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

- **Use a clear and descriptive title**
- **Provide a step-by-step description of the suggested enhancement**
- **Provide specific examples to demonstrate the steps**
- **Describe the current behavior** and **explain the expected behavior**
- **Explain why this enhancement would be useful**

### Pull Requests

- Follow the [Java style guide](#java-style-guide)
- Include appropriate test cases
- Update documentation as needed
- Ensure all tests pass before submitting
- Write clear commit messages

#### Process

1. Fork the repository
2. Create a new branch from `main` for your changes (`git checkout -b feat/your-feature-name`)
3. Make your changes
4. Commit your changes with clear messages
5. Push to your fork
6. Submit a pull request with a clear description of your changes

## Java Style Guide

- Use meaningful variable and method names
- Follow standard Java naming conventions (camelCase for variables/methods, PascalCase for classes)
- Keep methods focused and reasonably sized
- Use proper exception handling
- Add JavaDoc comments for public APIs
- Keep lines reasonably formatted (aim for under 120 characters)

## Development Setup

### Prerequisites

- Java 17 or 21
- Maven 3.6+

### Building

```bash
mvn clean package
```

### Testing

```bash
mvn clean test
```

### Writing Tests

- Place test classes in `src/test/java/` mirroring the source structure
- Test classes should end with `Test` or `Tests` suffix
- Use JUnit 5 (`@Test`, `@BeforeEach`, etc.)
- Use Mockito for mocking Keycloak dependencies (`@Mock`, `@InjectMocks`)
- Aim for at least 80% code coverage
- Write descriptive test names using `@DisplayName` annotation

## Code of Conduct

We are committed to providing a welcoming and inspiring community for all. Please read and adhere to our code of conduct:

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on what is best for the community
- Show empathy towards other community members

## License

By contributing to keycloak-gsis-provider, you agree that your contributions will be licensed under its Apache License 2.0.

## Questions?

Don't hesitate to open an issue with the `question` label or reach out to the maintainers.

Thank you for contributing to keycloak-gsis-provider!
