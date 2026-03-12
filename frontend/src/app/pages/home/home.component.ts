import { Component, OnInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService, Usuario } from '../../services/auth.service';

@Component({
  selector: 'app-home',
  standalone: true,
  imports: [CommonModule],
  templateUrl: './home.component.html',
  styleUrls: ['./home.component.css']
})
export class HomeComponent implements OnInit {
  tokenPreview = '';
  usuarios: Usuario[] = [];
  loadingUsuarios = false;
  errorUsuarios = '';

  constructor(private authService: AuthService) {}

  ngOnInit(): void {
    const token = this.authService.getToken() || '';
    // Muestra solo los primeros 50 caracteres para no exponer el token completo
    this.tokenPreview = token.substring(0, 50) + '...';
  }

  logout(): void {
    this.authService.logout();
  }

  cargarUsuarios(): void {
    this.loadingUsuarios = true;
    this.errorUsuarios = '';

    this.authService.getUsuarios().subscribe({
      next: (data) => {
        this.usuarios = data;
        this.loadingUsuarios = false;
      },
      error: (err) => {
        this.errorUsuarios = err.error?.message || 'Error al cargar usuarios';
        this.loadingUsuarios = false;
      }
    });
  }
}
