import { render, screen } from '@testing-library/react';
import App from './App';


test('renders RSA Secure Chat heading', () => {
  render(<App />);
  const heading = screen.getByText(/RSA Secure Chat/i);
  expect(heading).toBeInTheDocument();
});
