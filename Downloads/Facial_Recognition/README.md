# FaceAuth - Advanced Facial Recognition Authentication System

![FaceAuth Logo](https://img.shields.io/badge/FaceAuth-2.3.1-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Next.js](https://img.shields.io/badge/Next.js-14.2.5-black)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-14.5-blue)

FaceAuth is a comprehensive facial recognition authentication system that provides secure, biometric-based access control for applications. It combines advanced facial recognition technology with robust security features to deliver a reliable authentication solution.

## 🔑 Key Features

- **Facial Recognition Authentication**: Secure login using facial biometrics
- **Multi-factor Authentication**: Combine face recognition with traditional password authentication
- **Camera Management**: Support for various camera devices with validation and approval workflows
- **Security Monitoring**: Real-time detection of impostor attempts with alerts
- **Access Control**: Role-based permissions and access levels
- **Audit Logging**: Comprehensive logging of all authentication attempts
- **Admin Dashboard**: Intuitive interface for system management and monitoring
- **Developer API**: SDK for integration with other applications

## 🛠️ Technology Stack

- **Frontend**: Next.js 14, React 18, TypeScript, Tailwind CSS
- **Backend**: Next.js API Routes, Python FastAPI (face recognition service)
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: Custom auth system with session management
- **Face Recognition**: face_recognition library (Python), OpenCV
- **Security**: AES-256 encryption, PBKDF2 key derivation
- **Email**: SendGrid/Resend for notifications
- **Deployment**: Vercel (frontend), custom hosting (face recognition service)

## 📋 Prerequisites

- Node.js 18.x or higher
- Python 3.8 or higher
- PostgreSQL 14.x
- npm or yarn

## 🚀 Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/AymenAzizi/FaceAuth.git
cd FaceAuth
```

### 2. Install dependencies

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies
pip install face_recognition fastapi uvicorn python-dotenv pillow cryptography opencv-python
```

### 3. Set up the database

- Install PostgreSQL if not already installed
- Create a database named `facial_recognition`
- Update the `.env` file with your database credentials if needed

```bash
# Run Prisma migrations to set up the database schema
npx prisma migrate dev
```

### 4. Configure environment variables

The project uses a `.env` file for configuration. Make sure it contains:

```
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/facial_recognition"
ENCRYPTION_KEY=your_encryption_key
ENCRYPTION_SALT=your_encryption_salt
FACE_SERVICE_URL=http://localhost:8000
HOST=0.0.0.0
PORT=8000
ADMIN_EMAIL=your_email@example.com
RESEND_API_KEY=your_resend_api_key
RESEND_FROM_EMAIL=notifications@yourdomain.com
```

### 5. Start the services

```bash
# Start the Next.js frontend
npm run dev

# In a separate terminal, start the Python face recognition service
python python/face_service.py
```

### 6. Access the application

Open [http://localhost:3000](http://localhost:3000) in your browser to access the application.

## 🏗️ Project Structure

```
FaceAuth/
├── src/                  # Frontend and API routes
│   ├── app/              # Next.js app directory
│   │   ├── api/          # API routes
│   │   ├── dashboard/    # Dashboard pages
│   │   └── ...           # Other pages
│   ├── components/       # React components
│   ├── lib/              # Utility functions
│   └── pages/            # Additional pages
├── python/               # Python face recognition service
│   └── face_service.py   # FastAPI service
├── prisma/               # Prisma schema and migrations
│   └── schema.prisma     # Database schema
└── public/               # Static assets
```

## 🔒 Security Features

- **Encrypted Face Data**: All facial biometric data is encrypted using AES-256
- **Impostor Detection**: Advanced algorithms to detect spoofing attempts
- **Access Logging**: Comprehensive audit trail of all authentication attempts
- **Security Alerts**: Real-time notifications for suspicious activities
- **Session Management**: Secure session handling with expiration

## 🧪 Development and Testing

```bash
# Run linting
npm run lint

# Build for production
npm run build

# Start production server
npm start
```

## 📚 API Documentation

The system provides several API endpoints for authentication and management:

- `/api/auth/register` - User registration with facial recognition
- `/api/auth/face-login` - Facial authentication
- `/api/auth/signin` - Traditional password authentication
- `/api/camera/validate` - Camera validation
- `/api/access-logs` - Access logs retrieval
- `/api/security/impostor` - Impostor attempt handling

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For support, email support@faceauth.com or open an issue on GitHub.
