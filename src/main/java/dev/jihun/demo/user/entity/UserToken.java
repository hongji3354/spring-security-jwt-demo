package dev.jihun.demo.user.entity;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import javax.validation.constraints.NotEmpty;

@Getter
@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotEmpty
    private String refreshToken;

    @OneToOne(mappedBy = "userToken")
    private User user;

    public UserToken(final String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public void changeRefreshToken(final String refreshToken) {
        this.refreshToken = refreshToken;
    }
}
