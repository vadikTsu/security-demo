import {Component} from '@angular/core';
import {HttpClient, HttpHeaders, HttpResponse} from "@angular/common/http";
import {Observable} from "rxjs";

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrl: './app.component.css'
})
export class AppComponent {
  title = 'angular-jwt-example';
  loginRequest = {username: '', password: ''};
  protected?: string;

  constructor(private http: HttpClient) {
  }

  onLoginSubmit() {
    const username = this.loginRequest.username;
    const password = this.loginRequest.password;
    const basicAuthToken = `Basic ${encodeBase64(`${username}:${password}`)}`;

    const headers = new HttpHeaders({
      'Authorization': basicAuthToken,
      'Content-Type': 'application/json'
    });

    this.http.post("http://localhost:8080/Login", null, {headers, observe: 'response'})
      .subscribe(
        (response: HttpResponse<any>) => {
            alert("Logged in");
        },
        error => {
          console.log("Login error", error)
        }
      );
  }

  onGetResourceClick() {
    this.fetchData().subscribe(
      (response: HttpResponse<any>) => {
        this.protected = response.body.message;
      },
      error => {
        this.protected = '';
        if(error.status==403){
          alert("Token is expired, or has invalid data")
        }
      }
    );
  }

  fetchData(): Observable<HttpResponse<any>> {
    return this.http.get<any>("http://localhost:8080/protected", {observe: 'response'});
  }
}

function encodeBase64(str: string): string {
  return btoa(str);
}


